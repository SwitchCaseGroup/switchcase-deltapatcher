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
usage: patchtool.py [-h] [-s SRC] [-d DST] -p PCH [-x [SPLIT [SPLIT ...]]]
                    [-c {bz2,gzip,none}] [-v]
                    [{generate,apply,validate,analyze}]

Example to generate patch directory, apply it and then validate:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d out_dir -p patch_dir
  python3 patchtool.py validate -s src_dir -d out_dir -p patch_dir

Patching can also be done in-place, over top of the source directory:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d src_dir -p patch_dir
  python3 patchtool.py validate -d src_dir -p patch_dir

Patch apply uses atomic file operations. If the process is interrupted,
the apply command can be run again to resume patching.

Validation can be done on either one or both of src/dst directories:
  python3 patchtool.py validate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py validate -s src_dir -p patch_dir
  python3 patchtool.py validate -d dst_dir -p patch_dir

This allows a patch to be validated before and/or after in-place patching.

positional arguments:
  {generate,apply,validate,analyze}
                        command

optional arguments:
  -h, --help            show this help message and exit
  -s SRC, --src SRC     source directory
  -d DST, --dst DST     destination directory
  -p PCH, --patch PCH   patch directory
  -x [SPLIT [SPLIT ...]], --split [SPLIT [SPLIT ...]]
                        zero or more split file extensions
  -c {bz2,gzip,none}, --zip {bz2,gzip,none}
                        patch file zip
  -v, --verbose         increase verbosity
```


## Performance

With arbitrary hardware looking to patch ExpressoGame with Unreal Engine 4.14.3 to Unreal Engine 4.25.1 we saw the following results.

| Task         | Elapsed Time |
|--------------|--------------|
| Generation   |  3m 48s      |
| Copy of 4.25 |  7m 35s      |
| Apply        |  4m 15s      |

## Patch size

Generating a patch between ExpressoGame versions, we saw the following results for patch size.

|  Directory   |  Size (GB)   |
|--------------|--------------|
|  4.14.3      |  36.10 GB    |
|  4.25.1      |  35.90 GB    |
|  Patch       |   0.99 GB    |

## Style

This uses [flake8](https://flake8.pycqa.org/en/latest/) for Style Enforcement.
Any overrides can be found in the `.flake8` file in the root of the project.

## Testing

It uses [pytest](https://docs.pytest.org/en/stable/contents.html) and the tests live in the `tests` directory
