# interactivefitness-deltapatcher

This is delta patching software which extends [Xdelta](http://xdelta.org/) to patch directories instead of just individual files. Source and destination directories are analyzed to determine differences, and a patch directory representing their differences in generated. This patch folder can then be used to reconstruct the destination directory from the original source directory.

| Tool         | Source    | Destination | Patch         |
| ------------ | --------- | ----------- | ------------- |
| XDelta3      | file1.dat | file2.dat   | patch.xdelta3 |
| patchtool.py | folder1/  | folder2/    | patch/        |


## Setup

The script depends on python3 that comes standard with Ubuntu 18.04 and XDelta3 from Universe
 
On ubuntu this can be installed as follows:

```bash
apt-get install python3-full xdelta3
```


## Command-line usage

```
usage: patchtool.py [-h] [-s SRC] [-d DST] -p PCH [-x [SPLIT [SPLIT ...]]]
                    [-c {bz2,gzip,none}] [-v]
                    [{generate,apply,validate,analyze}]

Example to generate patch directory, apply it and then validate:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d out_dir -p patch_dir
  python3 patchtool.py validate -s src_dir -d out_dir -p patch_dir

```


## Performance

With arbitrary hardware looking to patch ExpressoGame with Unreal Engine 4.14.3 to Unreal Engine 4.25.1 we saw the following results with bzip compression enabled. 

| Task         | Elapsed Time |
| ------------ | ------------ |
| Generation   | 3m 48s       |
| Copy of 4.25 | 7m 35s       |
| Apply        | 4m 15s       |

## Patch size

Generating a patch between ExpressoGame versions, we saw the following results for patch size.

| Directory | Size (GB) |
| --------- | --------- |
| 4.14.3    | 36.10 GB  |
| 4.25.1    | 35.90 GB  |
| Patch     | 0.99 GB   |

## Style

This uses [flake8](https://flake8.pycqa.org/en/latest/) for Style Enforcement.
Any overrides can be found in the `.flake8` file in the root of the project.

## Testing

It uses [pytest](https://docs.pytest.org/en/stable/contents.html) and the tests live in the `tests` directory
