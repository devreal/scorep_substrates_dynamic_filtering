#define UNW_LOCAL_ONLY
#define _GNU_SOURCE /* <- needed for libunwind so stack_t is known */

#include <stddef.h> /* <- needs to come before libunwind for size_t */
#include <errno.h>
#include <fcntl.h>
#include <libunwind.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>

#include <dlfcn.h>

#include <scorep/SCOREP_SubstratePlugins.h>

/**
 * Default to own built-in hash function.
 */
#ifndef HASH_FUNCTION
#define HASH_FUNCTION HASH_OWN
#endif

/**
 * Simple identity hash function.
 *
 * This has proven slightly faster than the internal uthash hash functions.
 */
#define HASH_OWN( key, keylen, hashv )                                                            \
{                                                                                                 \
    hashv = *key;                                                                                 \
}

#include "uthash.h"

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Value to which the num_active field is set to signal that the region is to be deleted */
#define DELETION_SIGNAL (INT32_MIN)

/* Minimum number of calls before any filtering kicks in */
#define MIN_NUM_CALLS 100

/* Number of events between updates of the mean time used for dynamic filtering */
#define DYNAMIC_UPDATE_INTERVAL 1000

/**
 * Stores region info.
 */
typedef struct region_info
{
    /** Handle for uthash usage */
    UT_hash_handle hh;
    /** Number of threads active in this region (negative if to be deleted) */
    int64_t  num_active;
    /** The Score-P region handle */
    SCOREP_RegionHandle region_handle;
    /** Global counter for region entries */
    uint64_t call_cnt;
    /** Global calculated region duration */
    uint64_t duration;
    /** Timestamp of last enter into this region (used by main thread) */
    uint64_t last_enter;
    /** Human readable name of the region */
    char* region_name;
    /** Mean region duration used for comparison */
    float mean_duration;
    /** Marks whether the region has been marked for deletion */
    bool inactive;
    /** Marks whether the region is optimized beyond repair */
    bool optimized;
} region_info;

/** Global list of defined regions */
static region_info* regions = NULL;

/** General mutex used as a guard for writing region info */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

/** Mutex to protect the update of the meantime */
static pthread_mutex_t mean_duration_mtx = PTHREAD_MUTEX_INITIALIZER;

/** Flag indicating the filtering method to be used (true = absolute, false = relative) */
static bool filtering_absolute = true;

/** Threshold for filtering */
static unsigned long long threshold = 100000;

/** Mean duration across all regions */
static float mean_duration = 0;

/** Internal substrates id */
static size_t id;

/** Internal substrates callbacks for information retrieval about handles */
static const SCOREP_SubstratePluginCallbacks* callbacks;

/** Name of the enter region instrumentation call */
static char* enter_func = NULL;

/** IP of the enter region instrumentation call */
static char *enter_func_ip = NULL;

/** Name of the exit region instrumentation call */
static char* exit_func = NULL;

/** IP of the exit region instrumentation call */
static char *exit_func_ip = NULL;

/** Whether to continue despite having detected strong optimizations */
static bool continue_despite = true;

/** Whether to create an optimization report */
static bool create_report = false;

/** Whether to write a filter file */
static bool create_filter = false;

typedef struct region_stack_elem_t region_stack_elem_t;
struct region_stack_elem_t {
  region_stack_elem_t        *next;
  region_info                *region;
  uint64_t                    timestamp;
};

static __thread region_stack_elem_t *shadow_stack = NULL;
static __thread region_stack_elem_t *region_stack_freelist = NULL;

static inline void shadow_stack_push(region_info *region, uint64_t timestamp)
{
    region_stack_elem_t *elem;
    if (region_stack_freelist != NULL) {
        elem = region_stack_freelist;
        region_stack_freelist = elem->next;
        elem->next = NULL;
    } else {
        elem = malloc(sizeof(*elem));
    }

    elem->region = region;
    elem->timestamp = timestamp;
    elem->next   = shadow_stack;
    shadow_stack = elem;
}

static inline region_info* shadow_stack_pop(void)
{
    region_stack_elem_t *elem = shadow_stack;
    region_info         *ret  = elem->region;
    shadow_stack = elem->next;

    /* push elem onto freelist */
    elem->next = region_stack_freelist;
    region_stack_freelist = elem;

    return ret;
}


static inline region_stack_elem_t* shadow_stack_top(void)
{
    return shadow_stack;
}

static inline bool shadow_stack_empty()
{
    return shadow_stack == NULL;
}

static inline void shadow_stack_cleanup()
{
    region_stack_elem_t *elem;
    while (!shadow_stack_empty()) shadow_stack_pop();
    while (NULL != (elem = region_stack_freelist)) {
        region_stack_freelist = elem->next;
        free(elem);
    }
}

/**
 * Update the mean duration of all regions.
 *
 * Only used if the plugin uses the relative filtering method.
 */
static void update_mean_duration( )
{
    // don't update on every call
    static __thread uint64_t update_count = 0;
    if (++update_count < DYNAMIC_UPDATE_INTERVAL) return;

    // skip if another thread is already updating
    if (0 != pthread_mutex_trylock(&mean_duration_mtx)) return;

    update_count = 0;

    region_info *current, *tmp;
    uint64_t ctr = 1;
    float new_duration = 0;

    HASH_ITER( hh, regions, current, tmp )
    {
        // Only use active regions for calculating the mean duration.
        if( !current->inactive )
        {
            new_duration += current->mean_duration;
            ctr++;
        }
    }

    mean_duration = new_duration / ctr;

    pthread_mutex_unlock(&mean_duration_mtx);
}

/**
 * Overwrites a callq at the given position with a five byte NOP.
 *
 * By calling mprotect right before and after writing the NOP this function ensures that the correct
 * part of the TXT segment is writable and it's only writable as long as needed.
 *
 * @param   ptr                             Position of the callq to overwrite.
 */
static void overwrite_callq( char*                                             ptr )
{
    // the NOP used to overwrite the instrumentation call
    const char nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
    // check whether another thread has already overwritten it
    bool all_same = true;
    for (size_t i = 0; i < sizeof(nop); ++i) {
        if (nop[i] != ptr[i]) {
            all_same = false;
            break;
        }
    }
    if (all_same) return;
    // Get the page size of the system we're running on.
    size_t page_size = sysconf( _SC_PAGE_SIZE );
    // The callq may span two different pages and mprotect changes access permissions
    // on a per page basis, so we need to change the access permission on the pages where the first
    // and the last byte of the callq reside.
    void* first_page  = (void*)(((intptr_t)ptr)   & ~(page_size - 1));
    void* second_page = (void*)(((intptr_t)ptr+4) & ~(page_size - 1));

    // Add the write permission.
    if( mprotect( first_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC ) != 0
     || (first_page != second_page && mprotect( second_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC ) != 0 ))
    {
        fprintf( stderr,  "Could not add write permission to memory access rights on position "
                          "%p", ptr );
    }
    // Finally write that NOP.
    memmove( ptr, nop, sizeof( nop ) );

    // Remove the write permission.
    if( mprotect( first_page, page_size, PROT_READ | PROT_EXEC ) != 0
     || (first_page != second_page && mprotect( second_page, page_size, PROT_READ | PROT_EXEC ) != 0 ))
    {
        fprintf( stderr,  "Could not remove write permission to memory access rights on position "
                          "%p", ptr );
    }
}

/**
 * Checks which instrumentation call is used in the binary.
 *
 * Walks down the call path and searches for all known instrumentation functions (enter functions,
 * as this one should be called within a enter instrumentation call). The type found is stored for
 * later use in get_function_call_ip.
 */
static void get_instrumentation_call_type( )
{
    unw_cursor_t cursor;
    unw_context_t uc;
    unw_word_t offset;
    char sym[256];

    unw_getcontext( &uc );
    unw_init_local( &cursor, &uc );

    // Step up the call path...
    while( unw_step( &cursor ) > 0 )
    {
        // ... and check the function name against all know instrumentation call names.
        unw_get_proc_name( &cursor, sym, sizeof( sym ), &offset );

        if( strncmp( sym, "__cyg_profile_func_enter", 24 ) == 0 )
        {
            enter_func = "__cyg_profile_func_enter";
            exit_func = "__cyg_profile_func_exit";
            return;
        }
        else if( strncmp( sym, "scorep_plugin_enter_region", 26 ) == 0 )
        {
            enter_func = "scorep_plugin_enter_region";
            exit_func = "scorep_plugin_exit_region";
            return;
        }
        else if( strncmp( sym, "__VT_IntelEntry", 15 ) == 0 )
        {
            enter_func = "__VT_IntelEntry";
            exit_func = "__VT_IntelExit";
            return;
        }
    }
}

/**
 * Returns the instruction pointer for the given function.
 *
 * This method walks down the call path and tries to find a function with the given name and
 * returns a pointer for the first byte of the call to this function in the current call path.
 * Note that only the first (beginning from the innermost function) occurrence of the function call
 * will be handled.
 *
 * @param   function_name                   The function to look up.
 *
 * @return                                  Pointer to the first byte of the call to the given
 *                                          function in the current call path.
 */
static bool printed_warning;

#define DISPLACEMENT(JMPQ_ADDRESS) \
    (((int64_t) JMPQ_ADDRESS[4])<<24 | ((int64_t) JMPQ_ADDRESS[3])<<16 | ((int64_t) JMPQ_ADDRESS[2])<<8 | ((int64_t) JMPQ_ADDRESS[1]))

static char *get_instrumentation_call_ip(unw_context_t *uc, int is_enter)
{
    if (is_enter) {
        if (enter_func_ip != NULL) return enter_func_ip;
    } else {
        if (exit_func_ip != NULL) return exit_func_ip;
    }

    unw_cursor_t cursor;
    unw_word_t offset;
    char sym[256];

    unw_init_local( &cursor, uc );

    // Step up the call path...
    while( unw_step( &cursor ) > 0 )
    {
        int ret;
        unw_word_t ip;
        // ... and check the function name against all know instrumentation call names.
        ret = unw_get_proc_name( &cursor, sym, sizeof( sym ), &offset );
        if (ret != 0) fprintf(stderr, "WARN: unw_get_proc_name returned %d\n", ret);
        unw_get_reg( &cursor, UNW_REG_IP, &ip );

        if (is_enter) {
            if( strcmp( sym, enter_func ) == 0 )
            {
                printf("Found ENTER func IP %p\n", ip);
                enter_func_ip = (char*)ip;
                return enter_func_ip;
            }
        } else {
            if( strcmp( sym, exit_func ) == 0 )
            {
                printf("Found EXIT func IP %p\n", ip);
                exit_func_ip = (char*)ip;
                return exit_func_ip;
            }
        }
    }

    return NULL;
}

static char* get_function_call_ip( int is_enter )
{
    unw_cursor_t cursor;
    unw_context_t uc;
    unw_word_t ip;

    unw_getcontext( &uc );

    char *instr_func_ip = get_instrumentation_call_ip(&uc, is_enter);
    assert(instr_func_ip != NULL);

    unw_init_local( &cursor, &uc );

    // Step up the call path...
    while( unw_step( &cursor ) > 0 )
    {
        unw_get_reg( &cursor, UNW_REG_IP, &ip );

        if ((char*)ip == instr_func_ip) {
            /* step up one more and treat that as the call-site */
            if ( unw_step( &cursor ) <= 0 ) {
#ifdef DYNAMIC_FILTERING_DEBUG
                fprintf(stderr, "Failed to step out of Score-P instrumentation function  %s (%p)\n", is_enter ? enter_func : exit_func, instr_func_ip);
#endif
                return NULL;
            }
            unw_get_reg( &cursor, UNW_REG_IP, &ip );
            char* assumed= (char*) ( ip - 5 );
            return assumed;
        }
    }

    // This shouldn't happen, if we're on this point, we tried to delete a function not present in
    // the current call path. We return zero in this case because delete_regions wont try to delete
    // this call in this case and we get no undefined behaviour.
    return NULL;
}

/**
 * Pre-Enter region.
 *
 * This registers an active thread on the region. If the region has been marked
 * to be deleted the \c ignore flag is set. If there are no active threads in this
 * region, the instrumentation point is removed by the calling thread.
 * Note that multiple threads may attempt to remove the same instrumentation point,
 * which should not cause any harm.
 *
 * @param   scorep_location                 unused
 * @param   timestamp                       unused
 * @param   region_handle                   The region that is entered.
 * @param   ignore                          Set to 1 if the region should be ignored.
 */
static void on_pre_enter_region( __attribute__((unused)) struct SCOREP_Location*    scorep_location,
                                 uint64_t                                           timestamp,
                                 SCOREP_RegionHandle                                region_handle,
                                 int*                                               ignore )
{

    if( callbacks->SCOREP_RegionHandle_GetParadigmType( region_handle ) != SCOREP_PARADIGM_COMPILER )
    {
        return;
    }

    region_info* region;
    HASH_FIND( hh, regions, &region_handle, sizeof( uint32_t ), region );

    // Once per runtime determine which instrumentation calls are used in this binary.
    if( unlikely(!enter_func || !exit_func) )
    {
        pthread_mutex_lock(&mtx);
        if( !enter_func || !exit_func ) {
            get_instrumentation_call_type( );
            get_function_call_ip(true);
        }
        pthread_mutex_unlock(&mtx);
    }


    bool need_decrement = false;
    int64_t num_active = region->num_active;
    if (num_active >= 0) {
        num_active = __sync_fetch_and_add(&region->num_active, 1);
        need_decrement = true;
    }

    /* if the value is negative we signal that the region should be ignored */
    if (num_active < 0) {
        *ignore = 1;
        /* also mark as not active again */
        if (need_decrement) {
            num_active = __sync_fetch_and_sub(&region->num_active, 1);
        }
        /* if there are no other active threads we can safely delete it */
        // TODO: can we delete the *entery* point even if there are still active threads?
        // NOTE: wait until we have detected the exit_func_ip, otherwise libunwind seems to trip
        if (exit_func_ip != NULL) {
            /* serialize patching */
            pthread_mutex_lock(&mtx);
            char* ip = get_function_call_ip(true);
            if (ip == NULL) {
                fprintf(stderr, "Cannot remove enter instrumentation for function %s, unknown instrumentation?\n",
                        callbacks->SCOREP_RegionHandle_GetCanonicalName( region->region_handle ));
            } else {
                //printf("Patching out ENTER instrumentation for %s at IP %p\n", callbacks->SCOREP_RegionHandle_GetCanonicalName( region->region_handle ), ip);
                overwrite_callq(ip);
            }
            pthread_mutex_unlock(&mtx);
        }
    } else {
        // the region is active, push it onto shadow stack
        shadow_stack_push(region, timestamp);
    }

}

/**
 * Pre-Exit region.
 *
 * This method contains the code for calculating metrics (see on_enter as well) and the actual
 * instrumentation overwrite code.
 *
 * @param   scorep_location                 unused
 * @param   timestamp                       Time of the exit from the region.
 * @param   region_handle                   The region that is exited.
 * @param   metric_values                   unused
 */
static void on_pre_exit_region( __attribute__((unused)) struct SCOREP_Location*         scorep_location,
                                uint64_t                                                timestamp,
                                SCOREP_RegionHandle                                     region_handle,
                                int*                                                    ignore )
{
    if (printed_warning && !continue_despite) return;
    // Skip the undeletable functions!
    if( callbacks->SCOREP_RegionHandle_GetParadigmType( region_handle ) != SCOREP_PARADIGM_COMPILER )
    {
        return;
    }

    region_stack_elem_t *elem = shadow_stack_top();
    region_info* region;
    int64_t num_active;
    // if that region is on the shadow stack we can use it directly
    if (elem != NULL && region_handle == elem->region->region_handle) {
        region = elem->region;
        num_active = __sync_fetch_and_sub(&region->num_active, 1);
        shadow_stack_pop();
    } else {
        // otherwise get it from the hash table and signal to ignore it
        HASH_FIND( hh, regions, &region_handle, sizeof( uint32_t ), region );
        *ignore = 1;
        num_active = region->num_active;
    }

    // This function could be overwritten. Process it further.
    if( num_active > 0 )
    {

        if (region->optimized)
            return;

        // If the region already has been marked as inactive, skip the next steps.
        if( !region->inactive )
        {
            __sync_add_and_fetch(&region->duration, ( timestamp - elem->timestamp ));
            uint64_t call_cnt = __sync_add_and_fetch(&region->call_cnt, 1);

            if (MIN_NUM_CALLS < call_cnt) {

                if( filtering_absolute )
                {
                    // We're filtering absolute so just compare this region's mean duration with the
                    // threshold.
                    if( ( (float) region->duration / region->call_cnt ) < threshold )
                    {
                        region->inactive = true;
                    }
                }
                else
                {
                    // We're filtering relative so first update all regions' mean durations and then
                    // compare the duration of this region with the mean of all regions.
                    region->mean_duration = (float) region->duration / region->call_cnt;

                    update_mean_duration( );

                    if( region->mean_duration < mean_duration - threshold )
                    {
                        region->inactive = true;
                    }
                }
            }

            if (region->inactive) {
                int64_t num_active = __sync_add_and_fetch(&region->num_active, DELETION_SIGNAL);
                if (num_active < DELETION_SIGNAL) {
                    // someone else has signalled already, revert our signal
                    __sync_sub_and_fetch(&region->num_active, DELETION_SIGNAL);
                }
            }

        }
    }

    // if all threads have left the region we can safely delete the exit instrumentation
    // NOTE: wait until we have detected the enter_func_ip, otherwise libunwind seems to trip
    if (region->num_active == DELETION_SIGNAL && enter_func_ip != NULL) {
        pthread_mutex_lock(&mtx);
        char* ip = get_function_call_ip(false);
        if (ip == NULL) {
            fprintf(stderr, "Cannot remove exit instrumentation for function %s, unknown instrumentation?\n",
                    callbacks->SCOREP_RegionHandle_GetCanonicalName( region->region_handle ));
        } else {
            //printf("Patching out EXIT instrumentation for %s at IP %p\n", callbacks->SCOREP_RegionHandle_GetCanonicalName( region->region_handle ), ip);
            overwrite_callq(ip);
        }
        pthread_mutex_unlock(&mtx);
    }
}

/**
 * Call on Score-P's region definition event.
 *
 * Creates a new region_info struct in the global regions table for the newly defined region.
 *
 * @param   handle                          Generic handle type identifying the region.
 * @param   type                            Type specifier for the handle.
 */
static void on_define_region( SCOREP_AnyHandle                                      handle,
                              SCOREP_HandleType                                     type )
{
    if (printed_warning && !continue_despite) return;
    // This plugin can only handle compiler instrumentation, so we can safely ignore all other
    // regions.
    if( type != SCOREP_HANDLE_TYPE_REGION
        || callbacks->SCOREP_RegionHandle_GetParadigmType( handle ) != SCOREP_PARADIGM_COMPILER )
    {
        return;
    }

    region_info* new;

    // Check if this region handle is already registered, as this shouldn't happen.
    HASH_FIND( hh, regions, &handle, sizeof( uint32_t ), new );
    if( new == NULL )
    {
        const char* region_name = callbacks->SCOREP_RegionHandle_GetCanonicalName( handle );

        new = calloc( 1, sizeof( region_info ) );
        new->region_handle = handle;
        new->region_name = strdup(region_name);

        HASH_ADD( hh, regions, region_handle, sizeof( uint32_t ), new );
    }
    else
    {
        exit( EXIT_FAILURE );
    }
}

/**
 * Called whenever a location is created.
 *
 * When a location (e.g. an OpenMP thread) is created, we have to copy all region definitions into
 * a location-local storage to gain a lock free data access.
 *
 * @param   location                        The location which is created (unused).
 * @param   parent_location                 The location's parent location (unused).
 */
void on_create_location( __attribute__((unused)) const struct SCOREP_Location*            location,
                         __attribute__((unused)) const struct SCOREP_Location*            parent_location )
{
    // TODO: is this callback still needed?
    if (printed_warning && !continue_despite) return;
}

/**
 * Called whenever a location is deleted.
 *
 * If a location (e.g. a OpenMP thread) is deleted, its data is not needed any longer. So it can
 * safely be deleted.
 *
 * @param   location                        The location which is deleted (unused).
 */
void on_delete_location( __attribute__((unused)) const struct SCOREP_Location*            location )
{
    // clean up this thread's shadow stack and freelist
    if (!shadow_stack_empty()) {
        fprintf(stderr, "WARN: shadow of thread not empty!");
    }

    shadow_stack_cleanup();
}

/**
 * The plugin's initialization method.
 *
 * Just sets some default values and reads some environment variables.
 */
static int init( void )
{
    // Get the threshold for filtering.
    char* env_str = getenv( "SCOREP_SUBSTRATE_DYNAMIC_FILTERING_THRESHOLD" );
    if( env_str != NULL )
    {
        threshold = strtoull( env_str, NULL, 10 );
        if( threshold == 0 )
        {
            fprintf( stderr, "Unable to parse SCOREP_SUBSTRATE_DYNAMIC_FILTERING_THRESHOLD or set "
                             "to 0.\n" );
            exit( EXIT_FAILURE );
        }
    }

    // Get the wanted filtering method.
    env_str = getenv( "SCOREP_SUBSTRATE_DYNAMIC_FILTERING_METHOD" );
    filtering_absolute = true;
    if( env_str != NULL )
    {
        if( strcmp( env_str, "dynamic" ) == 0 )
        {
            filtering_absolute = false;
        }
    }

    // Get the wanted filtering method.
    env_str = getenv( "SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CONTINUE_DESPITE_FAILURE" );
    if( env_str != NULL )
    {
        if( strcmp( env_str, "true" ) == 0 || strcmp( env_str, "True" ) == 0 || strcmp( env_str, "TRUE" ) == 0 || strcmp( env_str, "1" ) == 0 )
        {
            continue_despite = true;
        }
    }

    // Get the wanted filtering method.
    env_str = getenv( "SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CREATE_REPORT" );
    if( env_str != NULL )
    {
        if( strcmp( env_str, "true" ) == 0 || strcmp( env_str, "True" ) == 0 || strcmp( env_str, "TRUE" ) == 0 || strcmp( env_str, "1" ) == 0 )
        {
            create_report = true;
        }
    }

    // Get the wanted filtering method.
    env_str = getenv( "SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CREATE_FILTER_FILE" );
    if( env_str != NULL )
    {
        if( strcmp( env_str, "true" ) == 0 || strcmp( env_str, "True" ) == 0 || strcmp( env_str, "TRUE" ) == 0 || strcmp( env_str, "1" ) == 0 )
        {
            create_filter = true;
        }
    }

    return 0;
}

/**
 * Gets the internal Score-P id for this plugin.
 *
 * The id is needed in order to give a proper return value in the finalizing method.
 *
 * @param   s_id                            Score-Ps internal id for this plugin.
 */
static void assign( size_t                                                          s_id )
{
    id = s_id;
}

/**
 * Debug output at the end of the program.
 *
 * Only used if the plugin has been built with -DBUILD_DEBUG=on.
 */
static void on_write_data( void )
{
    if ( create_report )
    {
        fprintf( stderr, "\n\nFinalizing.\n\n\n" );
        fprintf( stderr, "Global mean duration: %f\n\n", mean_duration );
        fprintf( stderr, "|                  Region Name                  "
                         "| Region handle "
                         "| Call count "
                         "|        Duration        "
                         "|   Mean duration  "
                         "|       Status       |\n" );
        region_info *current, *tmp;

        HASH_ITER( hh, regions, current, tmp )
        {
            fprintf( stderr, "| %-45s | %13d | %10lu | %22lu | %16.2f | %-18s |\n",
                        current->region_name,
                        current->region_handle,
                        current->call_cnt,
                        current->duration,
                        current->mean_duration,
                        current->optimized ? "compiler-optimized" : current->inactive ? "inactive" : " " );
        }
    }

    if ( create_filter )
    {
        const char *experiment_dir = callbacks->SCOREP_GetExperimentDirName();
        size_t experiment_dir_len = strlen(experiment_dir);
        size_t filename_len = experiment_dir_len + 16 + 10 + 1;
        char *filename = malloc(filename_len);
        int ret = snprintf( filename, filename_len, "%s/df-filter.list.%d", experiment_dir, getpid() );
        if (ret < 0 || filename_len < (size_t)ret) {
            printf("Failed to create filter file (filename truncated?)\n");
            free(filename);
            return;
        }
        printf("%s\n",filename);
        size_t backup_len = filename_len + 4;
        char *backup = malloc(backup_len);
        snprintf( backup, backup_len, "%s.old", filename );

        int fd = open( filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR );
        if( fd < 0 && errno == EEXIST )
        {
            // File could not be created because it already exists. Let's move it as a backup.
            rename( filename, backup );
            fd = open( filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR );
        }

        if( fd > 0 )
        {
            // File could be created. Write a Score-P filter file to it.
            FILE* fp = fdopen( fd, "w" );

            fprintf( fp, "SCOREP_REGION_NAMES_BEGIN\n" );

            region_info *current, *tmp;
            bool first = true;

            HASH_ITER( hh, regions, current, tmp )
            {
                if( current->inactive || current->optimized )
                {
                    if( first )
                    {
                        fprintf( fp, "EXCLUDE MANGLED %s\n", current->region_name );
                        first = false;
                    }
                    else
                    {
                        fprintf( fp, "        %s\n", current->region_name );
                    }
                }
            }

            fprintf( fp, "SCOREP_REGION_NAMES_END\n" );
            fclose( fp );
        }
        else
        {
            // File still could not be created. Dump an error message.
            fprintf( stderr, "Couldn't create filter list.\n" );
        }
        free(filename);
        free(backup);
    }
}

/**
 * Finalizing method.
 *
 * Used for cleanup and writing the filter file.
 */
static void finalize( void )
{

    region_info *current, *tmp;

    HASH_ITER( hh, regions, current, tmp )
    {
        HASH_DEL( regions, current );
        free( current );
    }

    regions = NULL;
}



/* we need the output folder, therefore we tell Score-P about it */
static bool get_requirement( SCOREP_Substrates_RequirementFlag flag )
{
  switch ( flag )
  {
      case SCOREP_SUBSTRATES_REQUIREMENT_CREATE_EXPERIMENT_DIRECTORY:
          return 1;
      default:
          return 0;
  }
}

/**
 * Defines callbacks for events.
 *
 * Defines callbacks for all events that are handled by this plugin.
 *
 * @param   mode                            unused
 * @param   functions                       Struct containing all available events.
 */
static uint32_t event_functions( __attribute__((unused)) SCOREP_Substrates_Mode     mode,
                                 SCOREP_Substrates_Callback**                       functions )
{
    SCOREP_Substrates_Callback* ret = calloc( SCOREP_SUBSTRATES_NUM_EVENTS,
                                                    sizeof( SCOREP_Substrates_Callback ) );

    ret[SCOREP_EVENT_PRE_ENTER_REGION] = (SCOREP_Substrates_Callback) on_pre_enter_region;
    ret[SCOREP_EVENT_PRE_EXIT_REGION]  = (SCOREP_Substrates_Callback) on_pre_exit_region;

    *functions = ret;
    return SCOREP_SUBSTRATES_NUM_EVENTS;
}

/**
 * Gets the callbacks for information retrieval about handles.
 *
 * Just stores the callbacks used by this plugin for later use.
 *
 * @param   callbacks                       The callbacks to be stored.
 * @param   size                            The size of the struct containing the callbacks.
 *                                          (unused)
 */
static void set_callbacks (   const SCOREP_SubstratePluginCallbacks*          incoming_callbacks,
                              __attribute__((unused)) size_t                                 size )
{
    assert( sizeof( SCOREP_SubstratePluginCallbacks ) <= size );
    callbacks = incoming_callbacks;
}

/**
 * Registers the plugin in Score-Ps interface.
 *
 * Sets management callbacks as well as the standard plugin version.
 */
SCOREP_SUBSTRATE_PLUGIN_ENTRY( dynamic_filtering )
{
    SCOREP_SubstratePluginInfo info;
    memset( &info, 0, sizeof( SCOREP_SubstratePluginInfo ) );

    info.init                   = init;
    info.assign_id              = assign;
    info.finalize               = finalize;
    info.new_definition_handle  = on_define_region;
    info.create_location        = on_create_location;
    info.delete_location        = on_delete_location;
    info.write_data             = on_write_data;
    info.get_event_functions    = event_functions;
    info.set_callbacks          = set_callbacks;
    info.get_requirement       = get_requirement;

    info.plugin_version         = SCOREP_SUBSTRATE_PLUGIN_VERSION;

    return info;
}
