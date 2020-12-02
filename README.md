# Dynamic Filtering Plugin for Score-P

This plugin filters instrumentation calls from a binary instrumented with Score-P. Filtered calls
are overwritten with `NOP`s to minimize overhead.

This work has been part of Philipp Trommlers bachelor's thesis. Results will be made available as soon as they're ready.


## Changes from the original implementation

This fork is based on the [original implementation](https://github.com/rschoene/scorep_substrates_dynamic_filtering).
The main differences are as follows:

- The instrumentation call-site detection was modified to use a **callee-based mechanism**: the call-site is detected by moving up one stack level from Score-P's instrumention function that is being called. The original implementation used a caller-based mechanism, which looked for the `call` instruction with the target pointing to the instrumention function. Unfortunately, this scheme does not work with dynamically linked Score-P libraries as the PLT indirection cannot be detected. The new scheme reliably works with both static and dynamic Score-P libraries. However, the new mechanism indiscriminatorily patches the call-site of the stack frame in which the instrumention function resides. It is thus important that your application is **built without sibling call optimization (by specifying `-fno-optimize-sibling-calls`, see the Known issues section below)** as otherwise the *call to the instrumented function* will be removed instead of the *instrumentation call*. Unfortunately, there is no way to otherwise avoid this optimization or to reliably detect it.

- This version of the plugin relies on an **experimental substrate plugin API extension of Score-P**, which adds filtering hooks to region-enter and -exit event handling calls and allows the plugin to prevent any state changes within Score-P if a filtered function is detected. The patch necessary for Score-P 6.0 can be found in the `scorep` directory. Compilation of the plugin will fail with vanilla Score-P 6.0.

- By using the new filter hooks, the plugin can **filter multiple call-sites of the same region**, which is important for inlined C/C++ functions.

- The filtering hooks also allow for **multiple threads to remove instrumention immediately** instead of relying on single-threaded execution after a join to remove instrumentation by the main thread. This has been useful in dealing with non-OpenMP parallelization schemes such as Intel TBB.

## Compilation and Installation

### Prerequisites

To compile this plugin, you need:

* C compiler (with `--std=c11` support)

* CMake

* Score-P installation

* `libunwind`

### Building

1. Create a build directory

        mkdir build
        cd build

2. Invoke CMake

        cmake ..

    If your Score-P installation is in a non-standard path, you have to manually pass that path to
    CMake:

        cmake .. -DSCOREP_CONFIG=<PATH_TO_YOUR_SCOREP_ROOT_DIR>/bin/scorep-config

    If your libunwind installation is in a non-standard path, you have to manually pass that path
    to CMake:

        cmake .. -DLIBUNWIND_ROOT=<PATH_TO_YOUR_LIBUNWIND_ROOT_DIR>

    If you want to build the plugin with a more verbose debug output, you can invoke CMake as
    follows:

        cmake .. -DBUILD_DEBUG=on

    This plugin defaults to the identity function as the hash for `uthash` as this has proven
    slightly faster than the built-ins of `uthash`. However, if you experience performance issues
    during hash table access, you can choose one of the built-in functions as mentioned
    [here](http://troydhanson.github.io/uthash/userguide.html#hash_functions), e.g.:

        cmake .. -DHASH_FUNCTION=HASH_JEN

3. Invoke make

        make

4. Copy the resulting library to a directory listed in `LD_LIBRARY_PATH` or add the current path to
    `LD_LIBRARY_PATH` with

        export LD_LIBRARY_PATH=`pwd`:$LD_LIBRARY_PATH

## Usage

In order to use this plugin, you have to add it to the `SCOREP_SUBSTRATES_PLUGINS` environment
variable.

    export SCOREP_SUBSTRATE_PLUGINS="dynamic_filtering"

The configuration of the plugin is done via environment variables.

### Environment variables

* `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_METHOD` (string)

    Specifies the metric used by the plugin to determine the instrumentation calls to be filtered.
    Currently supported are `absolute` (filter all functions with a duration below a given
    threshold) and `relative` (filter all functions with a duration below the mean duration of all functions minus a given threshold).

* `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_THRESHOLD` (integer, default 100000)

    Specifies the threshold to be used by the metrics in Score-P ticks (depends on SCOREP_TIMER)
    See `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_METHOD` for details.

* `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CONTINUE_DESPITE_FAILURE` 

    If set to `true`, `True`, `TRUE`, or `1` the plugin will continue to work even though it detected, that the program has been compiled with optimizations that make re-writing impossible (see Known issues).
    
* `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CREATE_REPORT` 

    If set to `true`, `True`, `TRUE`, or `1` the plugin will write a report to stderr when finished
    
* `SCOREP_SUBSTRATE_DYNAMIC_FILTERING_CREATE_FILTER_FILE` 

    If set to `true`, `True`, `TRUE`, or `1` the plugin will write a filter file to the experiment directory
    
    
    
    
### Known issues
The compiler optimization `-foptimize-sibling-calls` is usually enabled for icc/gcc at -O2 and -O3. This option allows the compiler to replace `call` instructions with `jmp` instruction if the called function can safely be executed in the same stack frame. **The plugin will not detect this automatically!** It is likely that your application will provide wrong results in this case. If you want to avoid this, but still use the other optimizations, just pass `-fno-optimize-sibling-calls` to your compiler.

### If anything fails

1. Check whether the plugin library can be loaded from the `LD_LIBRARY_PATH`

2. Check whether you provide sane values for the environment variables.

3. Check that your application was built with the `-fno-optimize-sibling-calls` compiler option.

4. Open an [issue on Github](https://github.com/Ferruck/scorep_substrates_dynamic_filtering/issues).

## License

For information regarding the license of this plugin, see
[LICENSE](https://github.com/Ferruck/scorep_substrates_dynamic_filtering/blob/master/LICENSE), for
the license of `uthash` see
[uthash.LICENSE](https://github.com/Ferruck/scorep_substrates_dynamic_filtering/blob/master/uthash.LICENSE).

## Authors

* Philipp Trommler (https://github.com/Ferruck)
* Robert Schoene (robert dot schoene at tu-dresden dot de)
* Joseph Schuchart (joseph dot schuchart at hlrs dot de)
