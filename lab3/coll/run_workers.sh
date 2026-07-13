#!/bin/bash

N=${1:-2}
SCRIPT=${2:-worker.py}

mkdir -p log
echo "=== Running $SCRIPT with $N workers (live output) ==="

for ((i=1; i<=N; i++)); do
    mx h$i python -u "$SCRIPT" $((i-1)) $N 2>&1 | tee "log/worker$i.log" &
done

wait
echo "=== All workers completed! ==="
