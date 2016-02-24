# ezfs

## Build

```
$ mkdir build && cd build
$ cmake .. && make
```

## Debug

Mount in foreground with debug output:

```
mkdir -p ${HOME}/tmp_mount
./build/ezfs -s -f -d ${HOME}/tmp_mount
```
