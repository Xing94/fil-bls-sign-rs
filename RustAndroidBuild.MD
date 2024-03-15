# Rust如何在Android环境下交叉编译
## 参考：[Android交叉编译mac配置](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html) 
## 当前操作是在mac系统下执行，windows请注意修改;
## 1.首先下载好sdk：
找到 `Android SDK > SDK Tools`，如果是在Android studio中，mac系统打开：`Android Studio > Preferences > Appearance & Behaviour > Android SDK > SDK Tools`，windows系统请打开setting中寻找。最后检查一下选项：
```
* Android SDK Tools
* NDK
* CMake
* LLDB
```
## 2.配置环境变量(配置方法自行百度)：
```.env
export ANDROID_HOME=/Users/$USER/Library/Android/sdk
export NDK_HOME=$ANDROID_HOME/ndk-bundle
```
## 3.创建NDK目录(所需较大硬盘空间)：
```.env
mkdir NDK
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm64 --install-dir NDK/arm64
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch arm --install-dir NDK/arm
${NDK_HOME}/build/tools/make_standalone_toolchain.py --api 26 --arch x86 --install-dir NDK/x86
```
## 4.项目交叉编译配置：
创建`cargo-config.toml`文件，将NDK地址配置在里面，以及cpu架构对应的配置：
```.env
[target.aarch64-linux-android]
ar = "<project path>/NDK/arm64/bin/aarch64-linux-android-ar"
linker = "<project path>/NDK/arm64/bin/aarch64-linux-android-clang"

[target.armv7-linux-androideabi]
ar = "<project path>/NDK/arm/bin/arm-linux-androideabi-ar"
linker = "<project path>/NDK/arm/bin/arm-linux-androideabi-clang"

[target.i686-linux-android]
ar = "<project path>/NDK/x86/bin/i686-linux-android-ar"
linker = "<project path>/NDK/x86/bin/i686-linux-android-clang"
```
## 5.将cargo交叉编译配置信息添加到cargo目录下：
复制配置文件
```.env
cp cargo-config.toml ~/.cargo/config
```
继续添加新创建的Android体系结构，rustup以便我们可以在交叉编译期间使用它们：
```.env
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
```
## 6.rust jni配置：
我们声明我们需要 jni 库，这意味着我们需要将该库包含在 Cargo.toml 文件中。打开它，并在`[package]`和`[lib]`声明之间添加以下内容。
```.env
[target.'cfg(target_os="android")'.dependencies]
jni = { version = "0.16.0", default-features = false }
```
指定交叉编译的库，在`Cargo.toml`文件中的`[lib]`部分中指定，Android所需的是动态库，`.so`后缀
```.env
[lib]
crate-type = ["dylib"]
```
## 7.执行编译
在Terminal中打开项目地址，导航到`cargo`目录下运行以下命令
```.env
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target i686-linux-android --release
```
运行后生成的路径在：
```
<project path>/target
```
其中生成包与Android studio `jniLibs` 下架构对应为：
```.env
arm64-v7a = aarch64-linux-android
armeabi-v7a = armv7-linux-androideabi
x86 = i686-linux-android
```
生成so包之后，使用方式与c的so包一致。
## 8.备注：
### 1.rust最终输出文件在lib.rs文件中编写；
### 2.输出方法格式为 `Java_<项目包名>_<类名称>_<方法名称>`，例如：`Java_com_lxx_nativerust_FilecoinBlsSignUtil_filPrivateKeySign`；
### 3.在编写了交叉编译的方法时候，使用到jni一些类的时候，rust直接运行会报错，如需运行rust代码测试案例，请注释jni相关代码；
### 4.输出项目名称在`Cargo.toml`文件的`[package]`标签下`name`指定，为`System.loadLibrary`加载的值；
