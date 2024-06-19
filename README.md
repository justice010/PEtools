# PE 解释器控制台程序

这是一个用C/C++编写的PE（可移植可执行文件）解释器控制台程序。该程序包括解析和解释PE文件的功能。

## 文件说明

- **Global.cpp**：包含项目中使用的全局定义和函数。
- **Global.h**：与`Global.cpp`相关的头文件。声明了全局变量和函数原型。
- **PEtool.cpp**：包含PE解释器的主要功能。该文件包括解析和解释PE文件的逻辑。

## 前置要求

- Visual Studio 2022
- C++17 或更高版本

## 构建项目

1. **克隆仓库**：
   ```sh
   git clone https://github.com/justice010/PEtools.git
   cd PEtools
2. **打开项目**：
- 使用Visual Studio 2022打开解决方案文件（`.sln`）。
3. **选择构建配置**：
- 在Visual Studio中，选择`x86`构建配置。如果没有`x86`配置，请在配置管理器中创建一个新的`x86`配置。
4. **生成解决方案**：
- 在菜单栏中，选择`生成` > `生成解决方案`或者按`F7`。确保所有项目都成功构建。

## 运行项目
- 在Visual Studio中，按`F5`键运行项目。程序将启动并对用户预定义的PE文件路径进行解析和解释。

## 贡献
欢迎提交issue和pull request以改进此项目。

## 许可证
此项目使用[MIT 许可证](https://opensource.org/licenses/MIT)。