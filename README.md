# MCFG READER AND WRITER
### Small utility to unpack and repack EFS item files
#### THIS DOESNT WORK YET. IM JUST WORKING ON IT AND PUSHING CODE AS I GO
#### DONT USE THIS. IT WONT WORK

Small utilities to read and write carrier specific MBN files for Qualcomm modems.
These files are what make IMS work (or not) in some modems.

*****************************************************************************
    ## WARNING ##
                               
    If the file is bad you might end up making the ADSP crash!
*****************************************************************************

#### Usage:

`read_mcfg -i INPUT_FILE`


#### Arguments: 

  -i: Input file  (mcfg_sw.mbn)


### Build

1. Run `make`

This code uses SHA256 implementation from https://github.com/983/SHA-256
