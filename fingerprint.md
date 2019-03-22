# SPAM特征记录

* 2019.03.17 每10-15分钟, 注册3次后被Ban掉
* 2019.03.17 每10分钟, 登陆/添加购物车10次后被Ban掉

# fingerprint => sensor_data解密

### 1级片段

```
sensor_data := SEG_1 SEG_2 SEG_3 ";" SEG_4 ";" SEG_5 ";" SEG_6
```

```
1. 公钥

SEG_1: bmak["od"](bmak["cs"], bmak["api_public_key"])["slice"](0, 16)

2. 公钥加密
g = bmak["od"](bmak["cs"], bmak["api_public_key"])["slice"](0, 16)
w = Math["floor"](bmak["get_cf_date"]() / 36e5)

SEG_2: bmak["od"](w, g)

3. SENSOR_DATA域

`-1,2,-94,<编号>,` 以此字符串为分隔; 代表不同的业务含义.

SEG_3: 详见SENSOR_DATA部分

4. 计算耗时(计算SENSOR_DATA域的耗时)
start = bmak["get_cf_date"]()
// 计算SENSOR_DATA域
end = bmak["get_cf_date"]()

SEG_4: end - start

5. 计算耗时(脚本开始: startTracking耗时)
bmak["t_tst"] = bmak["get_cf_date"](),
bmak["startTracking"](),
bmak["tst"] = bmak["get_cf_date"]() - bmak["t_tst"],

SEG_5: bmak['tst']

6. 计算耗时(1级分段拼接耗时)

SEG_6: bmak["get_cf_date"]() - y
```

### SENSOR_DATA域详解

###### 版本号: -100

```
bmak["ver"] + "-1,2,-94,-100"
```

###### 浏览器特征:  -101

```
bmak['gd'] = function() {
     a +                // bmak['uar']()  User-Agent
    ",uaend," + 
    bmak["xagg"] +      // bmak['bc']() 浏览器事件添加器/宽高等关键函数或属性的有无
    "," + 
    bmak["psub"] +      // navigator["productSub"]
    "," + 
    bmak["lang"] +      // navigator["language"]
    "," + 
    bmak["prod"] +      // navigator["product"]
    "," + 
    bmak["plen"] +      // navigator["plugins"]["length"]
    "," + 
    bmak["pen"] +       // window["_phantom"]
    "," + 
    bmak["wen"] +       // window["webdriver"]
    "," + 
    bmak["den"] +       // window["domAutomation"]
    "," + 
    bmak["z1"] +        // bmak["pi"](bmak["start_ts"] / (bmak["y1"] * bmak["y1"])) . 在bmak['gd']中设置, 由bpd(sensor_data计算入口)触发.
    "," + 
    bmak["d3"] +        // bmak["x2"]() % 1e7 . 在bmak['to']中设置, 由startTracking()触发一次性调用.
    "," + 
    n +                 // window["screen"]["availWidth"]
    "," + 
    o +                 // window["screen"]["availHeight"]
    "," + 
    m +                 // window["screen"]["width"]
    "," + 
    r +                 // window["screen"]["height"]
    "," + 
    i +                 // window["innerWidth"]
    "," + 
    c +                 // window["innerHeight"]
    "," + 
    b +                 // window["outerWidth"]
    "," + 
    bmak["bd"]() +      // 检测浏览器关键特征. ,cpen:0,i1:0,dm:0,cwen:0,non:1,opc:0,fc:0,sc:0,wrc:1,isc:0,vib:1,bat:1,x11:0,x12:1
    "," + 
    t +                 // bmak["ab"](bmak['uar']()) . 浏览器User-Agent校验和
    "," + 
    s +                 // var d = Math["random"](); s = (d + "").slice(0, 11) + bmak['pi'](1e3 * d / 2). 随机串
    "," + 
    e +                 // bmak["start_ts"] / 2 开始时间
    ",loc:" + 
    bmak["loc"]         // 默认空.无代码修改.
}

n = bmak["gd"]()

n + "-1,2,-94,-101,"
```

###### 特殊事件支持情况: -105

```
  o = window["DeviceOrientationEvent"] ? "do_en" : "do_dis"
  m = window["DeviceMotionEvent"] ? "dm_en" : "dm_dis"
  r = window["TouchEvent"] ? "t_en" : "t_dis"
  i = o + "," + m + "," + r

i + "-1,2,-94,-105,"
```

###### 初始页面表单信息: -102

```
bmak["informinfo"] = bmak["forminfo"]() // startTracing时触发一次.

bmak["informinfo"] + "-1,2,-94,-102,"
```

###### 当前表单信息: -108

```
//表单元素的ID使用generateUuid生成. (app.min.js:289)

bmak['forminfo'] = function() {
    for (var a = "", t = "", e = document["getElementsByTagName"]("input"), n = -1, o = 0; o < e["length"]; o++) {
        var m = e[o]
          , r = bmak["ab"](m["getAttribute"]("name"))   // name属性校验和
          , i = bmak["ab"](m["getAttribute"]("id"))     // id属性校验和
          , c = m["getAttribute"]("required")           // 是否必填
          , b = null == c ? 0 : 1
          , d = m["getAttribute"]("type")               // 输入框类型
          , k = null == d ? -1 : bmak["get_type"](d)
          , s = m["getAttribute"]("autocomplete");
        null == s ? n = -1 : (s = s["toLowerCase"](),
        n = "off" == s ? 0 : "on" == s ? 1 : 2);
        var l = m["defaultValue"]
          , u = m["value"]
          , _ = 0
          , f = 0;
        l && 0 != l["length"] && (f = 1),
        !u || 0 == u["length"] || f && u == l || (_ = 1),
        2 != k && (a = a + k + "," + n + "," + _ + "," + b + "," + i + "," + r + "," + f + ";"),
        t = t + _ + ";"
    }
    return null == bmak["ins"] && (bmak["ins"] = t),
    bmak["cns"] = t,
    a
}
c = bmak["forminfo"]()

c + "-1,2,-94,-108,"
```

###### 键盘事件: -110

```
键盘事件处理器cka中产生此数据.

单次行为描述为:
<ke_cnt: 键盘事件个数> "," <ke_type: 事件类型> "," <timespan: 距离start_ts时间> "," <keyCode: 进行了分类> "," "0" <特殊键: 8421编码shift/ctrl/meta/alt> "," "821"

null != e["isTrusted"] && !1 === e["isTrusted"] 则追加: ",0"

bmak["kact"] + "-1,2,-94,-110,"
```

###### 鼠标事件: -117

```
鼠标事件处理器cma中产生此数据.

单次行为描述为: 
<me_cnt: 鼠标事件个数> "," <me_type: 事件类型> "," <timespan: 距离start_ts时间> "," <pageX> "," <pageY>
如果不是鼠标移动时间, 则追加: "," <target: 目标元素摘要>
如果不是鼠标移动事件, 并且点击的不是左键. 则追加: "," <which or button. 点击的键代码>

bmak["mact"] + "-1,2,-94,-117,"
```

###### 触屏事件: -111

```
触屏事件处理器cta中产生此数据.

bmak["tact"] + "-1,2,-94,-111,"
```

###### 设备方向事件: -109

```
设备方向事件处理器cdoa中产生此数据.

bmak["doact"] + "-1,2,-94,-109,"
```

###### 设备运动事件: -114

```
设备运动事件处理器cdma中产生此数据.

bmak["dmact"] + "-1,2,-94,-114,
```

###### 触点事件: -103

```
设备触点事件处理器cpa中产生此数据.

bmak["pact"] + "-1,2,-94,-103,"
```

###### 页面可见性事件: -112

```
可见性事件lvc中产生此数据.

bmak["vcact"] + "-1,2,-94,-112,"
```

###### 当前URL: -115

```
bmak['getdurl'] = function() {
    return bmak["enReadDocUrl"] ? document["URL"]["replace"](/\\|"/g, "") : ""
}
b = bmak["getdurl"]()

b + "-1,2,-94,-115,"
```

###### 各类事件校验和: -106

```
f = [
    bmak["ke_vel"] + 1, // 键盘事件
    bmak["me_vel"],     // 鼠标事件
    bmak["te_vel"],     // 触摸事件
    bmak["doe_vel"],    // 设备方向事件
    bmak["dme_vel"],    // 设备运动事件
    bmak["pe_vel"],     // 触点事件
    k,                  // 前6类事件校验和求和. bmak["ke_vel"] + bmak["me_vel"] + bmak["doe_vel"] + bmak["dme_vel"] + bmak["te_vel"] + bmak["pe_vel"]
    t,                  // bmak["get_cf_date"]() - bmak["start_ts"]. 从加载完到计算时的时间.
    bmak["init_time"],  // 固定0
    bmak["start_ts"],   // 脚本开始 => ir() => 设置start_ts为当前时间.
    bmak["fpcf"]["td"], // 计算fpValstr的耗时. 在bmak['fpcf']['fpVal']中. 代表bmak['fpcf']['data']的执行时间.
    bmak["d2"],         // bmak["pi"](bmak["z1"] / 23). 在bd中执行 <= bd由gd触发 <= gd在bpd开始调用.
                        // bmak['z1']在gd中计算. bmak["pi"](bmak["start_ts"] / (bmak["y1"] * bmak["y1"]))
    bmak["ke_cnt"],     // 键盘事件计数
    bmak["me_cnt"],     // 鼠标事件计数
    l,                  // bmak["pi"](bmak["d2"] / 6)
    bmak["pe_cnt"],     // 触点事件计数
    bmak["te_cnt"],     // 触屏事件计数
    s,                  // 时间差. bmak["get_cf_date"]() - bmak["start_ts"]
    bmak["ta"],         // 鼠标点击时间计数
    bmak["n_ck"],       // 是否有cookie: _abck=
    e,                  // Cookie[_abck]的值
    bmak["ab"](e),      // Cookie[_abck]的校验和
    bmak["fpcf"]["rVal"],   // 指纹计算中随机图像写入的随机数字. [0 - 999]
    bmak["fpcf"]["rCFP"],   // 指纹计算的结果. (一个固定图像/一个随机图像) 参见bmak['fpcf']['canvas']方法.
    u                       // 浏览器一系列特征的校验和.
].join(',')
f + "-1,2,-94,-106,"
```

###### ajax请求类型和编号: -119

```
bmak["aj_type"] + "," + bmak["aj_indx"] + "-1,2,-94,-119,"
```

###### 一些数学函数和类型函数的性能评估: -122

```
getmr: function() {
    try {
        if ("undefined" == typeof performance || void 0 === performance["now"] || "undefined" == typeof JSON)
            return void (bmak["mr"] = "undef");
        for (var a = "", t = 1e3, e = [Math["abs"], Math["acos"], Math["asin"], Math["atanh"], Math["cbrt"], Math["exp"], Math["random"], Math["round"], Math["sqrt"], isFinite, isNaN, parseFloat, parseInt, JSON["parse"]], n = 0; n < e["length"]; n++) {
            var o = []
              , m = 0
              , r = performance["now"]()
              , i = 0
              , c = 0;
            if (void 0 !== e[n]) {
                for (i = 0; i < t && m < .6; i++) {
                    for (var b = performance["now"](), d = 0; d < 4e3; d++) // 动态执行10000次, 评估性能.
                        e[n](3.14);
                    var k = performance["now"]();
                    o["push"](Math["round"](1e3 * (k - b))),
                    m = k - r
                }
                var s = o["sort"]();
                c = s[Math["floor"](s["length"] / 2)] / 5
            }
            a = a + c + ","
        }
        bmak["mr"] = a
    } catch (a) {
        bmak["mr"] = "exception"
    }
}

bmak["mr"] + "-1,2,-94,-122,"
```

###### 浏览器Hack特征检测: -123

```
bmak['sed'] = function () {
    var a;
    a = window["$cdc_asdjflasutopfhvcZLmcfl_"] || document["$cdc_asdjflasutopfhvcZLmcfl_"] ? "1" : "0";
    var t;
    t = null != window["document"]["documentElement"]["getAttribute"]("webdriver") ? "1" : "0";
    var e;
    e = void 0 !== navigator["webdriver"] && navigator["webdriver"] ? "1" : "0";
    var n;
    n = void 0 !== window["webdriver"] ? "1" : "0";
    var o;
    o = void 0 !== window["XPathResult"] || void 0 !== document["XPathResult"] ? "1" : "0";
    var m;
    m = null != window["document"]["documentElement"]["getAttribute"]("driver") ? "1" : "0";
    var r;
    return r = null != window["document"]["documentElement"]["getAttribute"]("selenium") ? "1" : "0",
    [a, t, e, n, o, m, r]["join"](",")
}
v = bmak["sed"]()

v + "-1,2,-94,-123,"
```

###### 根据时间和随机数的一个算法计算: -70

```
mn_w是入口函数. 该函数每100ms执行一次, 执行10次以上, 会产生此数据

bmak["mn_r"] + "-1,2,-94,-70,"
```

###### 指纹签名结果: -80

```
bmak['fpcf']['fpVal']产生.

bmak["fpcf"]["fpValstr"] + "-1,2,-94,-80,"
```

###### 指纹签名结果校验和: -116

```
p = "" + bmak["ab"](bmak["fpcf"]["fpValstr"])

p + "-1,2,-94,-116,"
```

###### 一个特殊校验和: -118

```
在bmak['to']中设置, 由startTracking()触发一次性调用.

bmak["o9"] + "-1,2,-94,-118,"
```

###### 对-70之前的SENSOR_DATA域字符串计算校验和: -121

```
var h = bmak["ab"](bmak["sensor_data"]);

h + "-1,2,-94,-121,"
```
