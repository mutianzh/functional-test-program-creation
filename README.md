# functional-test-program-creation
An inductive learning based functional test program creation method

## Clone and build gem5-extension

```
git clone https://github.com/mutianzh/gem5-extension.git
cd gem5-extension
python3 $(which scons) build/RISCV/gem5.opt -j 30
```

## Install GNC tool for RISCV32

### Linux
TBD

### Windows

TBD

## Create and simulate an assembly test program

Clone the repo:
```
git clone https://github.com/mutianzh/functional-test-program-creation.git
```

```hello.py``` is an example file that creates an assembly test program, simulates it, and measure the coverage.
