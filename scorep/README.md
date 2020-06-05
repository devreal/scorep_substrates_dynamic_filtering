# Experimental Instrumentation Event Filter Hooks in Score-P 

This directory contains a patch for Score-P 6.0 to add experimental instrumentation filter hooks that allow substrate plugins to signal to Score-P that the current event should be ignored.
This can be helpful to suppress the handling of events that are slated for filtering.

Without these filtering hooks, the dynamic filtering plugin would be unable to reliably remove instrumentation points without breaking consistency of enter/leave events in the profiling and tracing substrates.

## How to apply
Download a copy of Score-P 6.0 from https://www.vi-hps.org/projects/score-p/ and unpack the tar file.
Change into the directory and apply the patch as follows:

```
$ git apply < /path/to/scorep_filter_hooks.patch
```

Configure and build Score-P as usual.
