English | [简体中文](README.zh-CN.md)

# NAOS Image Generator

Generate development and production NAOS firmware, plus system and Bootloader OTA update bundles.

## Quick start

Ubuntu 24.04 x86_64 with Python 3.11 or newer is recommended. The supplied tools require glibc 2.38 or newer.

Install the Python dependencies:

```bash
sudo apt-get install python3 python3-yaml python3-pycryptodome
```

Prepare your keys: development images need the signing private key and certificate in `key/ota/`. Production images also need secure boot keys, a system encryption key and an SSH CA public key. See “Keys and certificates” below for the file list, and the README in each key directory for generation instructions.

Run from the generator directory as a regular user:

```bash
./naos-image-generator.py
```

At startup, the generator checks Python dependencies, user namespaces and ARM64 QEMU/binfmt execution. If a requirement is missing, it reports the reason. Fix the issue and run it again.

Follow the menus:

1. Select `Development` or `Production`.
2. Choose a full firmware image, firmware with update bundles, or update bundles only.
3. Select the base board and Alpine version. Adjust capacity, device tree, SBOM and output directory as needed.
4. Review the `Summary` and confirm generation.

Press Enter to use the displayed default, or enter `q` to cancel. Image files are downloaded after the final confirmation. Collect the results from `output/` when generation finishes.

The final `Command:` line in the `Summary` reproduces your selections. Copy and run it from the same directory next time to skip the menus.

## Features and usage

### Development and production images

| Setting | Development | Production |
| --- | --- | --- |
| Intended use | Development and debugging | Production deployment |
| Secure boot | Disabled by default | Enabled by default |
| System and userdata encryption | Disabled by default | Enabled by default |
| RAUC update signature verification | Enabled | Enabled |
| SBOM | Disabled by default | Enabled by default |
| OTP/eFuse public-key hash programming | Disabled by default | Disabled by default |

### Choose what to generate

| Menu option | Output |
| --- | --- |
| `Full firmware image (.img)` | Full firmware ready to flash |
| `Full firmware image + system and bootloader updates` | Full firmware and both system and Bootloader update bundles |
| `System and bootloader updates` | System and Bootloader update bundles only |
| `Check image generation requirements` | Check the selected image, keys, tools and configuration |

OTA bundles are disabled by default. Select a menu option that includes updates, or use `--ota` or `--ota-only`.

### Directories

| Directory | Purpose |
| --- | --- |
| `.tools/` | Supplied tools |
| `key/` | Keys and certificates for signing, encryption and login |
| `files/` | Add or replace system configuration, application configuration and other files |
| `apks/` | Local application APKs to preinstall |
| `board/` | Optional device tree DTBs |
| `output/` | Generated firmware, update bundles and manifests |

### Keys and certificates

Prepare the files required for your image:

| Purpose | Files | Generation instructions |
| --- | --- | --- |
| OTA signing and verification | `key/ota/signing.key.pem`, `key/ota/signing.cert.pem` | [OTA README](key/ota/README) |
| Production secure boot | `key/secure-boot/dev.key`, `dev.crt`, `dev.pubkey` | [Secure boot README](key/secure-boot/README) |
| Production system encryption | `key/system-encryption/system.key` | [System encryption README](key/system-encryption/README) |
| Production SSH certificate login | `key/ssh-ca/ssh_ca_key.pub` | [SSH CA README](key/ssh-ca/README) |

Generating OTA bundles requires the signing private key and certificate. To change them, replace both files in `key/ota/`. The certificate is installed in the generated system to verify updates.

`system.key` must contain 64 lowercase hexadecimal characters with no trailing newline. Keep only the public key in the SSH CA directory; store the private key separately.

Replace development keys with your own before releasing firmware. Updates for existing devices must use matching OTA, secure boot and system encryption keys. Devices with a programmed public-key hash must continue to use the matching secure boot key.

### Add or replace system configuration

Create files under `files/` using their intended paths on the device. For example:

```text
files/
└── etc/
    ├── motd
    └── naos-core/
        └── device.ini
```

During generation, `files/etc/motd` replaces the `/etc/motd` welcome message, and `files/etc/naos-core/device.ini` replaces `/etc/naos-core/device.ini`. Existing files are overwritten; missing files are added.

`files/` is applied after application APK installation, so it can also replace configuration supplied by those packages. Set executable permissions on scripts beforehand.

### Preinstall local application APKs

Place application `.apk` files directly in `apks/`:

```text
apks/
├── drm-firefox-0.2-r0.apk
└── my-app-1.0-r0.apk
```

- Use `aarch64` or `noarch` packages for RK3588.
- Installation is offline. Include any dependency packages that are missing from the base system in this directory.
- Local packages do not require a signing certificate.
- APK installation scripts and triggers run normally.
- If `apks/` is empty, no extra applications are installed.

Local APK installation also requires unprivileged user namespaces and working ARM64 QEMU/binfmt support on the host. Use the menu's requirements check to verify the environment.

#### Enable application services

An application package can include a `<package-name>.commands` file at its root to enable services or perform other configuration.

For example, `/drm-firefox.commands` in the `drm-firefox` package:

```sh
rc-update add start-firefox default
```

The corresponding service script, `/etc/init.d/start-firefox`, must also be included in the APK.

After all application packages are installed, the generator runs each package's `.commands` file. The filename must match the package name; each package uses its own file. A failed command stops generation. After successful execution, the command files are removed from the final system.

### Replace the device tree

For peripheral variants of the same core board, use a custom DTB to generate the corresponding firmware.

Place compiled `.dtb` files directly in `board/`:

```text
board/
└── vision1.dtb
```

A device tree selection menu appears, with the `.dtb` suffix omitted from the names:

```text
Device tree:
  1. mixtile-core3588e-v2
  2. vision1
```

The first option uses the device tree supplied with the image. Selecting `vision1` produces `vision1.img`; the output directory, update bundle filenames and SBOM filenames also use `vision1`.

The `machine` field in `/usr/lib/naos/version.json` is also set to `vision1`, so Core reports that name as `system_machine` to the update server. Selecting the default device tree keeps the base board name.

This step is hidden when `board/` contains no DTBs. Custom DTBs must support the same core board and the kernel in the selected image version.

### Adjust A/B partition sizes

Each system slot defaults to **200 MiB**. Press Enter at the capacity prompt to keep the default, or select `n` to enter another size, such as 150 MiB per slot.

On the command line, `--system-mib 150` sets both system A and system B to 150 MiB.

The menus use the image's default boot slot size. Boot slots contain the kernel and ramdisk. Use `--boot-mib` if you need to change their size; this does not refer to the U-Boot partition.

The full firmware starts with a 32 MiB userdata partition. The device expands it and creates the filesystem on first boot. OTA updates do not resize existing device partitions.

### Generate an SBOM

SBOM generation is enabled by default for production images and disabled for development images. Results are placed in the output directory:

- `*.spdx.json`: software bill of materials.
- `*.sbom.json`: manifest summary.

Application APKs can include SPDX 2.3 JSON, such as `/sbom.spdx.json` at the package root. It is extracted after installation and removed from the rootfs. When SBOM generation is enabled, it is merged into the final SBOM.

The selected image version must supply SBOM data. `--sbom` cannot create a complete SBOM for a version that lacks this data.

### Use OTA update bundles

Update generation produces two types of bundle:

| File | Purpose |
| --- | --- |
| `naos-bundle-<board>-<version>.raucb` | Update the system, kernel and ramdisk using A/B system slots |
| `naos-bootloader-bundle-<board>-<version>.raucb` | Update the Bootloader without switching system slots |

Copy a bundle to the device, then run as root on the device:

```bash
naos-core update /path/to/bundle.raucb
```

The command returns a task ID. Check its progress with:

```bash
naos-core task <task-id>
```

The system reboots automatically after a successful update.

### OTP/eFuse public-key hash programming

The final production image prompt asks whether to enable OTP/eFuse public-key hash programming. The default is `n`. Keep it disabled for development and testing.

After selecting `y`, choose one of these options:

| Mode | Output |
| --- | --- |
| Separate programming Loader | Additional `loader-efuse.bin` and `idblock-efuse.bin`; normal firmware keeps programming disabled |
| Firmware with programming enabled | Full firmware and Bootloader update bundle names have an `-efuse` suffix; the Loader is named `loader-efuse.bin` |

A second confirmation is required. **OTP/eFuse programming is irreversible. Using the wrong key can prevent the device from booting.** Confirm that you understand the risk and follow the instructions in the output directory.

The generator creates these files; it does not program a connected device.

### Configure automatic hawkBit registration

Set the following in `files/etc/naos-core/device.ini`:

```ini
[hawkbit]
enabled=true
server_url=https://updates.example.com
tenant=DEFAULT
token_type=gateway
token=REPLACE_WITH_GATEWAY_TOKEN
controller_id=
```

Replace the address, tenant and GatewayToken with your own values, and enable GatewayToken on the server. Set `server_url` to the server address, including a port if needed, without a tenant or API path.

When flashing the same image to multiple devices, leave `controller_id` empty. Each device generates and saves its own ID, then registers with the server after connecting to the network.

Configuration already saved on a device may take precedence over the new image's configuration. To change it, edit `/etc/naos-core/device.ini` on the device and run:

```bash
rc-service naos-core restart
```

## Command-line usage

Copy the `Command:` from the menu's `Summary` whenever possible. You can also specify arguments manually. Replace the version numbers below with the published version you need.

Generate full development firmware:

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-dev --image-version 0.0.3
```

Generate full production firmware and both update bundles:

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-prod --image-version 0.0.3 --ota
```

Use the `vision1` device tree and generate only the two update bundles:

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-prod --image-version 0.0.3 --dtb board/vision1.dtb --ota-only
```

Set each system slot to 150 MiB:

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-dev --image-version 0.0.3 --system-mib 150
```

Other common options:

| Option | Purpose |
| --- | --- |
| `--output PATH` | Set the output directory |
| `--dtb PATH` | Select a device tree |
| `--apks-dir PATH` | Set the local application package directory |
| `--sbom` / `--no-sbom` | Enable or disable SBOM generation |
| `--repository URL` | Change the image repository; default: `https://packages.naos.ai/repository` |
| `--cache-dir PATH` | Set the download cache directory |
| `--tools-dir PATH` | Set the tools directory |
| `--config PATH` | Use a custom YAML configuration |
| `--force` | Replace output previously created by the generator in the same directory |

The reproducible command includes `--force` so you can generate into the same output directory again. Run it from the same working directory with the corresponding keys, configuration, APKs and device tree files.

View the complete help:

```bash
./naos-image-generator.py --help
./naos-image-generator.py build --help
```

## Find generated files

Full firmware uses this default output directory:

```text
output/<board>/<development-or-production>/<version>/
```

Update bundles generated on their own use:

```text
output/<board>/<development-or-production>/<version>-updates/
```

Depending on your selections, the directory contains the full firmware `.img`, two `.raucb` bundles, SBOM files and a `manifest.json` describing the outputs. Full firmware generation also retains partition images, including boot and system images.
