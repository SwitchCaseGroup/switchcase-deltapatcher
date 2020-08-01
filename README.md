# interactivefitness-deltapatcher

This is delta patching software which uses [Xdelta](http://xdelta.org/) to create change sets of files allowing for storing these delta files to
patch a file to the new version without only needing to know the differences.


## Setup

The script depends on python3 that comes standard with Ubuntu 18.04 and XDelta3 from Universe
 
On ubuntu this can be installed as follows:

```bash
apt-get install python3-full xdelta3
```

## Usage

```bash
usage: patchtool.py [-h] -s SRC -d DST -p PCH [-x [SPLIT [SPLIT ...]]] [-v] [{generate,apply,validate}]

Example to generate patch directory, apply it and then validate:
  patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  patchtool.py apply -s src_dir -d out_dir -p patch_dir
  patchtool.py validate -s dst_dir -d out_dir -p patch_dir

Patching can also be done in-place, over top of the source directory:
  patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  patchtool.py apply -s src_dir -d src_dir -p patch_dir
  patchtool.py validate -s dst_dir -d src_dir -p patch_dir

Patch apply uses atomic file operations. If the process is interrupted,
the apply command can be run again to resume patching.

positional arguments:
  {generate,apply,validate}
                        command

optional arguments:
  -h, --help            show this help message and exit
  -s SRC, --src SRC     source directory
  -d DST, --dst DST     destination directory
  -p PCH, --patch PCH   patch directory
  -x [SPLIT [SPLIT ...]], --split [SPLIT [SPLIT ...]]
                        zero or more split file extensions
  -v, --verbose         increase verbosity
```


## Performance

With arbitrary hardware looking to patch ExpressoGame with Unreal Engine 4.14.3 to Unreal Engine 4.25.1 we saw the following results.

| Task         | Elapsed Time |
|--------------|--------------|
| Generation   | 43m 28s      |
| Copy of 4.25 |  7m 35s      |
| Apply        | 11m 37s      |

## Style

This uses [flake8](https://flake8.pycqa.org/en/latest/) for Style Enforcement.

## Testing

This has a general regression test as test.py which has its own command line options.

It also supports [pytest](https://docs.pytest.org/en/stable/contents.html)
