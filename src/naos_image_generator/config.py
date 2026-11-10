# SPDX-License-Identifier: MIT
"""One optional YAML configuration, with paths relative to that file."""
import os
from pathlib import Path

import yaml

from .common import BuildError, require


ALLOWED = {'input','output','version','build_id','epoch','partitions','layout','overlays','remove',
           'ota','ota_only','sbom','burn_key_hash','efuse_loader','keys','ssh_ca','ota_certificate','processors',
           'tools_dir','tools','additional_sbom','repository','image','image_version',
           'apk','apk_key','cache_dir','apks_dir','dtb'}


def path(value, base):
    require(isinstance(value, (str,Path)) and str(value), 'Expected a configuration path')
    expanded = os.path.expandvars(str(value))
    require('$' not in expanded, 'A configuration path contains an undefined environment variable')
    result = Path(expanded).expanduser()
    return (result if result.is_absolute() else Path(base)/result).resolve()


def load(filename=None):
    if filename is None:
        return {}, Path.cwd()
    filename = Path(filename).resolve()
    try:
        value = yaml.safe_load(filename.read_text())
        if value is None:
            value = {}
    except (OSError,yaml.YAMLError) as error:
        raise BuildError('Cannot read generator configuration: ' + str(filename)) from error
    require(isinstance(value,dict) and not (set(value)-ALLOWED), 'Unknown generator configuration option')
    for name in ('ota','ota_only','sbom','burn_key_hash','efuse_loader'):
        if name in value:
            require(type(value[name]) is bool, name + ' must be true or false')
    for name in ('overlays','remove','additional_sbom'):
        if name in value:
            require(isinstance(value[name],list), name + ' must be a list')
    for name in ('repository','image','image_version','apk','apk_key','cache_dir','apks_dir','dtb'):
        if name in value:
            require(isinstance(value[name],str) and bool(value[name]), name + ' must be a nonempty string')
    return value, filename.parent
