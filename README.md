# ptrack(?)

watch-exec but magic

## Development

<!-- maid-tasks -->

### build

```sh
mkdir -p build; cd ./build/
zig build-exe -lc ../src/main.zig --name ptrack
```

### test

```sh
./build/ptrack maid build
```
