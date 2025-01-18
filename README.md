# ptrack(?)

watch-exec but magic

## Development

<!-- maid-tasks -->

### build

```sh
mkdir -p build; cd ./build/
zig build-exe -lc ../src/main.zig --name ptrack
```

### run

```sh
maid build && ./build/ptrack
```
