[English](README.md) | 简体中文

# NAOS 镜像生成器

生成 NAOS 开发版、量产版固件，以及系统和 Bootloader OTA 升级包。

## 快速启动

推荐使用 Ubuntu 24.04 x86_64，Python 3.11 或更新版本。当前配套工具包要求 glibc 2.38 或更新版本。

安装 Python 依赖：

```bash
sudo apt-get install python3 python3-yaml python3-pycryptodome
```

准备密钥：开发版先准备 `key/ota/` 中的签名私钥和证书；量产版还需准备安全启动、系统加密和 SSH CA 公钥。文件清单见下文“密钥与证书”，生成方法见对应密钥目录的 README。

在生成器目录中，以普通用户运行：

```bash
./naos-image-generator.py
```

启动时会先检查 Python 依赖、用户命名空间和 ARM64 QEMU/binfmt 是否可用。环境不满足要求时会直接提示原因，修复后重新运行即可。

按菜单完成选择：

1. 选择开发版 `Development` 或量产版 `Production`。
2. 选择生成完整固件、固件加升级包，或仅生成升级包。
3. 选择基础板型和 Alpine 版本，按需调整容量、设备树、SBOM 和输出目录。
4. 检查 `Summary`，确认开始生成。

回车采用显示的默认值，输入 `q` 取消。镜像文件在最终确认后开始下载，生成完成后到 `output/` 下取产物。

`Summary` 最后一行的 `Command:` 是本次选择对应的完整命令。下次在相同目录直接复制执行，即可跳过菜单。

## 功能与使用

### 开发版与量产版

| 项目 | 开发版 | 量产版 |
| --- | --- | --- |
| 使用场景 | 开发和调试 | 正式部署 |
| 安全启动 | 默认关闭 | 默认开启 |
| 系统和用户分区加密 | 默认关闭 | 默认开启 |
| RAUC 升级包验签 | 保留 | 保留 |
| SBOM | 默认关闭 | 默认开启 |
| OTP/eFuse 公钥哈希烧写 | 默认关闭 | 默认关闭 |

### 选择生成内容

| 菜单选项 | 生成内容 |
| --- | --- |
| `Full firmware image (.img)` | 可用于烧写的完整固件 |
| `Full firmware image + system and bootloader updates` | 完整固件，以及系统和 Bootloader 两种升级包 |
| `System and bootloader updates` | 仅生成系统和 Bootloader 两种升级包 |
| `Check image generation requirements` | 检查所选镜像、密钥、工具和配置是否满足要求 |

OTA 升级包默认不生成，需要在菜单中选择包含升级包的选项，或使用 `--ota`、`--ota-only`。

### 目录说明

| 目录 | 用途 |
| --- | --- |
| `.tools/` | 配套工具包 |
| `key/` | 签名、加密和登录所需的密钥或证书 |
| `files/` | 添加或替换系统配置、应用配置及其他文件 |
| `apks/` | 预装的本地应用 APK |
| `board/` | 可选设备树 DTB |
| `output/` | 生成的固件、升级包和清单 |

### 密钥与证书

按需要准备以下文件：

| 用途 | 文件 | 生成说明 |
| --- | --- | --- |
| OTA 签名与验签 | `key/ota/signing.key.pem`、`key/ota/signing.cert.pem` | [OTA README](key/ota/README) |
| 量产版安全启动 | `key/secure-boot/dev.key`、`dev.crt`、`dev.pubkey` | [安全启动 README](key/secure-boot/README) |
| 量产版系统加密 | `key/system-encryption/system.key` | [系统加密 README](key/system-encryption/README) |
| 量产版 SSH 证书登录 | `key/ssh-ca/ssh_ca_key.pub` | [SSH CA README](key/ssh-ca/README) |

生成 OTA 包需要签名私钥和证书。更换时，将 `key/ota/` 中的两份文件一起替换；证书会写入生成的系统，作为升级包验签证书。

`system.key` 必须为 64 个小写十六进制字符，末尾不带换行。SSH CA 目录只放公钥，私钥单独保管。

正式发布前，将开发用密钥换成自己的密钥。给已有设备生成升级包时，应使用与设备匹配的 OTA、安全启动和系统加密密钥；已烧写公钥哈希的设备必须继续使用匹配的安全启动密钥。

### 添加或替换系统配置

在 `files/` 下，按照设备中的路径创建目录和文件。例如：

```text
files/
└── etc/
    ├── motd
    └── naos-core/
        └── device.ini
```

生成时，`files/etc/motd` 会替换系统的 `/etc/motd` 欢迎信息；`files/etc/naos-core/device.ini` 会替换 `/etc/naos-core/device.ini`。同名文件覆盖，不存在的文件会添加。

`files/` 在应用 APK 安装完成后应用，因此也可以替换应用包中的配置。可执行脚本需提前设置执行权限。

### 预装本地应用 APK

将自行准备的应用 `.apk` 文件直接放到 `apks/`。下面的 `example-app` 和 `example-addon` 都是虚构示例名称，使用时替换为自己的包。

```text
apks/
├── example-app-1.0-r0.apk
└── example-addon-1.0-r0.apk
```

- 使用 `aarch64` 或 `noarch` 包。
- 依赖由目标系统的 APK 安装器解析，缺少的包从其配置的仓库下载。
- 本地包无需提供签名证书。
- APK 自带的安装脚本和触发器会正常执行。
- `apks/` 为空时，不安装额外应用。

使用本地 APK 功能时，主机还需支持非特权用户命名空间，并具备 ARM64 QEMU/binfmt 执行支持。可通过菜单中的检查功能确认环境。

#### 应用依赖与安装脚本

在 APK 元数据中声明应用依赖，例如在 APKBUILD 中设置 `depends="libstdc++"`。生成时会在解压后的 rootfs 内调用 `/sbin/apk`，由它使用自己的 `/etc/apk/repositories`、架构和受信任公钥。已安装且版本满足要求的依赖直接复用，缺少的依赖及其递归依赖会自动下载；需要补充软件包时，生成环境应能访问网络。

也可以把依赖 APK 放入 `apks/`，例如配置仓库中没有的私有包。同一个本地包名只提供一个版本。APK 安装器负责检查依赖和版本约束；缺少软件包、版本不兼容或签名错误都会停止生成。

APK 安装脚本和触发器会在生成镜像时的目标环境中执行。`pre-install` 在包内文件展开前运行，`post-install` 在安装后运行；需要使用新安装文件的操作应放入 `post-install`。下文的可选 `.commands` 步骤则在全部本地包安装完成后执行。

#### 打包配置命令与应用 SBOM

配置命令和应用 SBOM 都应**打进 APK 包内**，再把生成的 `.apk` 放入生成器的 `apks/` 目录。生成器从已安装的包中读取这些文件；仅放在 APK 旁边的独立 `.commands` 或 SBOM 文件不会被使用。

以包名 `example-app` 为例，APK 内容应采用以下布局。这里表示包内文件安装到目标系统后的路径：

```text
/
├── example-app.commands
├── etc/
│   └── init.d/
│       └── example-app
└── usr/
    └── share/
        └── example-app/
            └── sbom.spdx.json
```

| APK 安装后的文件路径 | 用途 |
| --- | --- |
| `/example-app.commands` | 可选的镜像配置命令，在应用 APK 安装完成后执行 |
| `/etc/init.d/example-app` | OpenRC 服务脚本，权限设为 `0755` |
| `/usr/share/example-app/sbom.spdx.json` | 可选的应用 SBOM，格式为 SPDX 2.3 JSON |

命令文件必须命名为 `/<包名>.commands`，包名取自 APK 元数据中的 `pkgname`。当 `pkgname=example-app` 时，路径就是 `/example-app.commands`；即使 APK 文件名为 `example-app-1.0-r0.apk`，也不带版本号。命令文件权限为 `0644` 即可，生成器会在目标系统内使用 `/bin/sh -e` 执行。

例如，`/example-app.commands` 的内容为：

```sh
rc-update add example-app default
```

全部应用包安装完成后，生成器会执行各自的 `.commands` 文件。命令失败会停止生成；成功后，命令文件会从最终系统中移除。

多个应用包各用自己的命令文件和 SBOM 目录。例如，包名为 `example-addon` 时，可以包含 `/example-addon.commands` 和 `/usr/share/example-addon/sbom.spdx.json`。

### 更换设备树

同一核心板的不同外设版本，可通过更换 DTB 生成对应固件。

把编译好的 `.dtb` 文件直接放到 `board/`：

```text
board/
└── vision1.dtb
```

菜单中会增加设备树选择，显示名称时省略 `.dtb` 后缀：

```text
Device tree:
  1. mixtile-core3588e-v2
  2. vision1
```

第一项使用镜像自带的设备树。选择 `vision1` 后，完整固件命名为 `vision1.img`，输出目录、升级包和 SBOM 文件名也使用 `vision1`。

镜像内 `/usr/lib/naos/version.json` 的 `machine` 也会写为 `vision1`，Core 向更新平台上报的 `system_machine` 随之使用这个名字。使用默认设备树时保留基础板型名称。

`board/` 没有 DTB 时，不显示这一步。自定义 DTB 应适用于同一核心板及所选版本的内核。

### 调整 A/B 分区容量

每个 system 槽默认 **200 MiB**。容量选择中回车使用默认值；选择 `n` 后可输入其他容量，例如每槽 150 MiB。

命令行使用 `--system-mib 150`，会同时设置 system A 和 B 的容量。

boot 槽在菜单中使用镜像默认容量，包含内核和 ramdisk。需要调整时可使用 `--boot-mib`，它不代表 U-Boot 分区。

userdata 在完整固件中初始为 32 MiB，设备首次启动后自动扩容和创建文件系统。OTA 升级不会调整设备已有分区的容量。

### 生成 SBOM

量产版默认生成 SBOM，开发版默认关闭。生成结果放在输出目录中：

- `*.spdx.json`：软件物料清单。
- `*.sbom.json`：清单摘要。

应用 SBOM 应作为普通文件打进 APK，推荐安装路径为 `/usr/share/<包名>/sbom.spdx.json`，见[打包配置命令与应用 SBOM](#打包配置命令与应用-sbom)。每个包使用自己的目录，避免文件冲突。

生成器会扫描各本地 APK 所拥有的文件，目录不限，识别 `*.spdx.json`、`*.sbom.json` 和 `sbom.json`，文件名匹配不区分大小写；例如 `/example-app.spdx.json` 也支持。用于合并的文档必须为 SPDX 2.3 JSON。普通 JSON 摘要（如配套的 `*.sbom.json` 文件）会移除，但不会作为 SPDX 证据合并。

这些文件在 APK 安装过程中被取出并从 rootfs 中移除，即使没有开启整机 SBOM 也会执行。开启整机 SBOM 时，取出的 SPDX 文档会合并到最终镜像清单。之后通过生成器 `files/` 目录添加的文件，不在这一步 APK SBOM 提取范围内。

开启此功能需要所选镜像版本提供 SBOM 数据；未提供数据的版本不能仅通过 `--sbom` 补出清单。

### 使用 OTA 升级包

生成升级包时，会得到两类文件：

| 文件 | 用途 |
| --- | --- |
| `naos-bundle-<板型>-<版本>.raucb` | 更新系统、内核和 ramdisk，使用 A/B 系统槽升级 |
| `naos-bootloader-bundle-<板型>-<版本>.raucb` | 更新 Bootloader，不切换系统槽 |

将升级包复制到设备，在设备上以 root 执行：

```bash
naos-core update /path/to/bundle.raucb
```

命令返回任务 ID，可查看进度：

```bash
naos-core task <任务ID>
```

升级成功后系统会自动重启。

### OTP/eFuse 公钥哈希烧写选项

量产版最后会询问是否开启 OTP/eFuse 公钥哈希烧写，默认选择 `n`。开发和测试时保持关闭。

选择 `y` 后，可以选择：

| 方式 | 生成结果 |
| --- | --- |
| 单独生成烧写 Loader | 额外生成 `loader-efuse.bin` 和 `idblock-efuse.bin`，普通固件保持不烧写 |
| 生成带烧写功能的固件 | 完整固件和 Bootloader 升级包带 `-efuse` 后缀，Loader 名为 `loader-efuse.bin` |

此项需要二次确认。**OTP/eFuse 烧写不可撤销，错误的密钥可能导致设备无法启动。** 使用前确认已了解风险，并按输出目录中的说明操作。

镜像生成器负责生成这些文件，不会直接对连接的设备进行烧写。

### 配置 hawkBit 自动注册

在 `files/etc/naos-core/device.ini` 中填写：

```ini
[hawkbit]
enabled=true
server_url=https://updates.example.com
tenant=DEFAULT
token_type=gateway
token=REPLACE_WITH_GATEWAY_TOKEN
controller_id=
```

将地址、租户和 GatewayToken 换成自己的配置，并在服务端启用 GatewayToken。`server_url` 只填服务地址，可带端口，不追加租户或 API 路径。

同一镜像烧录到多台设备时，保持 `controller_id` 为空。设备联网后会自动生成并保存自己的 ID，再向服务器注册。

已有设备保存的配置可能优先于新镜像中的配置。需要修改时，在设备上编辑 `/etc/naos-core/device.ini`，然后执行：

```bash
rc-service naos-core restart
```

## 命令行使用

优先复制菜单 `Summary` 中的 `Command:`。也可以手动指定参数，以下示例中的版本号请换成需要的已发布版本。

生成开发版完整固件：

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-dev --image-version 0.0.3
```

生成量产版完整固件及两种升级包：

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-prod --image-version 0.0.3 --ota
```

使用 `vision1` 设备树，仅生成两种升级包：

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-prod --image-version 0.0.3 --dtb board/vision1.dtb --ota-only
```

设置每个 system 槽为 150 MiB：

```bash
./naos-image-generator.py build --image mixtile-core3588e-v2-alpine-dev --image-version 0.0.3 --system-mib 150
```

其他常用参数：

| 参数 | 作用 |
| --- | --- |
| `--output PATH` | 指定输出目录 |
| `--dtb PATH` | 指定设备树 |
| `--apks-dir PATH` | 指定本地应用包目录 |
| `--sbom` / `--no-sbom` | 开启或关闭 SBOM |
| `--repository URL` | 更换镜像仓库，默认 `https://packages.naos.ai/repository` |
| `--cache-dir PATH` | 指定下载缓存目录 |
| `--tools-dir PATH` | 指定配套工具包目录 |
| `--config PATH` | 使用自定义 YAML 配置 |
| `--force` | 替换同一目录中之前由生成器创建的产物 |

复现命令会带上 `--force`，方便再次生成到同一输出目录。执行时保持相同工作目录，以及对应的密钥、配置、APK 和设备树文件。

查看完整帮助：

```bash
./naos-image-generator.py --help
./naos-image-generator.py build --help
```

## 查找生成结果

完整固件默认位于：

```text
output/<板型>/<development或production>/<版本>/
```

仅生成升级包时，目录为：

```text
output/<板型>/<development或production>/<版本>-updates/
```

根据选择，目录中会包含完整固件 `.img`、两种 `.raucb` 升级包、SBOM，以及记录产物信息的 `manifest.json`。完整固件模式还会保留启动和系统等分区镜像。
