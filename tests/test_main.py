import pytest
import subprocess
import argparse
import random
import shutil
import json
import sys
import re
import os
import io

from patchtool import PatchTool


@pytest.fixture
def same_patch():
    '''Returns a Patch Tool instance with no changes'''
    return PatchTool(".", ".", "/var/tmp", [], True)


@pytest.fixture
def patch():
    '''Returns a Patch Tool instance with changes'''
    return PatchTool(".", "..", "/var/tmp", [], True)


def test_default_same_patch(same_patch):
    assert same_patch.src == same_patch.dst


def test_default_diff_patch(patch):
    assert patch.src != patch.dst
