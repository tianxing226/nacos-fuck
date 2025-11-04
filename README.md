# Nacos-fuck
本工具是一个专业的Nacos安全检测脚本，用于自动化检测Nacos系统中存在的常见安全漏洞。工具采用多线程技术，可快速对单个目标或批量目标进行漏洞扫描，并生成详细的检测报告
## 🛸Nacos-fuck工具免责声明​

### 🛸1. 目的与范围​

本工具名为“Nacos安全检测工具”，是一款专为安全研究、漏洞验证和教育学习而设计的软件。​其唯一合法用途是用于授权下的安全评估、渗透测试（需获得明确书面授权）、学术研究或个人在隔离测试环境中的学习。任何未经授权对他人系统或网络进行扫描、测试或攻击的行为均属违法，与本工具作者无关

核心检测能力​：

🔍 ​弱口令检测​：测试默认凭证nacos/nacos

🔍 ​伪造JWT创建账户漏洞​：检测身份认证绕过漏洞

🔍 ​Derby SQL注入漏洞​：检测CNVD-2020-67618漏洞

🔍 ​未授权查看用户信息漏洞​：检测用户信息泄露漏洞

****二、系统环境要求****

**基本要求**

​Python版本​：Python 3.6或更高版本

依赖库安装
````
```
pip install requests colorama urllib3 tqdm

**基本命令格式**

python nacos-fuck.py [选项]

```
````
**参数说明**
````
**参数--------简写-------说明-------默认值**

--help        -h        说明

--input       -i      指定目标文件路径       url.txt

--url         -u      扫描单个URL           无

--threads     -t      设置扫描线程数        10

--timeout     -T      设置请求超时时间（秒） 6

````

**解压后本地默认有个url.txt将你需要批量扫描的url复制到里面一行一个url，后使用python nacos-fuck.py运行即可，运行过程中可使用ctrl+c退出扫描。**

**部分使用截图**
<img width="1730" height="923" alt="image" src="https://github.com/user-attachments/assets/93f39a50-ab0e-4844-9e17-6364fe71012a" />

<img width="1730" height="924" alt="image" src="https://github.com/user-attachments/assets/790d0f2e-56de-4633-962e-105d0ac0ff21" />

#### 帮我点个Satr吧,QAQ
