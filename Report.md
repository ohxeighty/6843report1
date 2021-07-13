## Insecure Access Control

**Vulnerability:** Clientside Session Validation via Cookies

**Severity:** Critical

**Description:** The logic for controlling a client's session is dependent upon an insecure clientside cookie. This allows an attacker to authenticate themselves into an administrative session without legitimate credentials. 

**Remediation:** Ideally divorce the session validation and creation logic + data from the client. If this is not possible (i.e. stateless application), utilise existing rigorous frameworks for storing session data on the client, such as JWTs. 

**Asset Domain:** sales.quoccabank.com

### Writeup 
We note that the server establishes a base64 encoded cookie named `metadata` with a decoded value of `admin=0`. Sending requests with the `metadata` cookie set to the base64 encoded value of `admin=1` (`YWRtaW49MQ==`) authenticates us into the admin dashboard. 

![Alt](/Images/Pasted%20image%2020210713163115.png)
![Alt](/Images/Pasted%20image%2020210713163200.png)
![Alt](/Images/Pasted%20image%2020210713163218.png)

## SQLi in Payment Portal Query

**Vulnerability:** SQL Injection in `period` parameter

**Severity:** Critical

**Description:** The `period` parameter is vulnerable to SQL injection, allowing execution of arbitrary SQL statements. An attacker may exfiltrate records in the local database or escalate to RCE depending on the environment. 

**Remediation:** Make use of the prepared statements binding provided in the appropriate backend framework. Refer to `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html` for further guidance.

**Asset Domain:** pay-portal.quoccabank.com

### Writeup
By experimenting with common bad characters we notice that a double quote (`"`) in the period parameter causes the server to throw a syntax error - clueing us into the exploitable SQLi vulnerability. 
![Alt](/Images/Pasted%20image%2020210713163400.png)

We use a double quote to escape the string context, leaving us free to control the logic in this selection - as a POC we invoke a traditional `or '1'='1'` payload to dump all rows followed by a semicolon and comment delimiter; making sure to encode a whitespace character after the double-dash (see `https://dev.mysql.com/doc/refman/5.7/en/comments.html`). 

`https://pay-portal.quoccabank.com/?period=1%22%20or%20%271%27%20=%20%271%27;%20--`

![Alt](/Images/Pasted%20image%2020210713163417.png)

With regards to full exploitation - since stacked queries are not enabled here, we would apply union selection techniques to extract data in band (e.g. looting information_schema then appropriate tables). A lack of write privileges makes RCE proper unlikely. 

## SQLi Login Bypass

**Vulnerability:** SQL Injection in Login Parameters

**Severity:** Critical

**Description:** The login parameters (e.g. `susername`) are vulnerable to SQL injection, allowing an attacker to authenticate without credentials to the `bigapp` web service with any privileges. 

**Remediation:** Make use of the prepared statements binding provided in the appropriate backend framework. Refer to `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html` for further guidance.

**Asset Domain:** bigapp.quoccabank.com

### Writeup
We can escape the context of the username string by injecting a single quote into the `susername` POST parameter. We can now modify the logic of the selection statement. For instance, to authenticate as the administrative user, we could constrain the email parameter to `admin@quoccabank.com` and skip the password validation by ending the query and commenting further logic out.
`susername=admin@quoccabank.com'%3b--+&spassword=password&login-submit=Secure+Log+In++`
![Alt](/Images/Pasted%20image%2020210713162915.png)
![Alt](/Images/Pasted%20image%2020210713162920.png)

## SQLi in Registration Page

**Vulnerability:** SQL Injection in Registration Page

**Severity:** High

**Description:** The `email` parameter in the `create.html` registration endpoint is vulnerable to SQL Injection, allowing execution of arbitrary SQL statements. Injecting into this `insert` statement allows both record exfiltration (using either boolean or timebased methods) and record modification / creation. For example, an attacker could take advantage of the `ON DUPLICATE KEY UPDATE` directive to overwrite the credentials of the administrative user. 

**Remediation:** Make use of the prepared statements binding provided in the appropriate backend framework. Refer to `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html` for further guidance.

**Asset Domain:** bigapp.quoccabank.com 

### Writeup
By appending `'or '1'='1` to a benign email in the `email` parameter, we notice we can tamper with the backend SQL logic (note the resulting error message).
![Alt](/Images/Pasted%20image%2020210713161609.png)
![Alt](/Images/Pasted%20image%2020210713161903.png)

## Incorrect Handling of Methods in Login Page

**Vulnerability:** No Distinction Between GET and POST Methods in Login Endpoint

**Severity:** Low

**Description:** The backend `bigapp` webserver does not distinguish between POST and GET parameters, enabling authentication through GET requests. For example,
`https://bigapp.quoccabank.com/login.html?susername=admin@quoccabank.com&spassword=Admin@123` would result in a successful login. 
This issue is included for completeness. 

**Remediation:** Process only POST parameters in the login endpoint. 

**Asset Domain:** bigapp.quoccabank.com 

## SQLi in REST API

**Vulnerability:** SQL Injection in REST API

**Severity:** Critical

**Description:** The `q` parameter in the REST API is vulnerable to SQL Injection, allowing execution of arbitrary SQL statements. An attacker may exfiltrate records in the local database or escalate to RCE depending on the environment. 

**Remediation:** Make use of the prepared statements binding provided in the appropriate backend framework. Refer to `https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html` for further guidance.

**Asset Domain:** bigapp.quoccabank.com

### Writeup
Injecting a single quote into the `q` parameter causes the backend to spit out an error message, which helpfully prints out some of the query that we are injecting into. 
` '%' OR pname LIKE '%'%') AND bu IS NOT NULL) ORDER BY categor`. 
Parsing this syntax allows us to construct our payload:
* We need a quote to escape the string context
* In a similar fashion, we need two right brackets
We test our payload by manually closing out the query:
`https://bigapp.quoccabank.com/api/v1/bproducts?q=A%27));%20--%20%20`
Since this does not throw any errors (and returns nothing, as expected), we are free to proceed. 
![Alt](/Images/Pasted%20image%2020210713164517.png)

First, we enumerate the number of columns that are pulled by the query. We accomplish this with a union select, increasing the number of columns until we no longer get an error.
`https://bigapp.quoccabank.com/api/v1/bproducts?q=A%27))%20union%20all%20select%201,2,3,4,5,6;%20--%20garbage`

![Alt](/Images/Pasted%20image%2020210713164536.png)

Since all 6 columns are visible in the response, we are free to pick any columns as our output for in band exfiltration. First, we dump `information_schema.tables`:
`https://bigapp.quoccabank.com/api/v1/bproducts?q=A%27))%20union%20all%20select%201,table_name,3,4,5,6%20from%20information_schema.tables;%20--%20garbage`

![Alt](/Images/Pasted%20image%2020210713164557.png)

We take special note of the `bproducts` and `users` table - the only non default tables. 

From here, we can start dumping sensitive information, e.g.
`https://bigapp.quoccabank.com/api/v1/bproducts?q=A%27))%20union%20all%20select%201,column_name,3,4,5,6%20from%20information_schema.columns%20where%20table_name=%27users%27;%20--%20`
will dump the structure of the `users` table, which we can then loot:
![Alt](/Images/Pasted%20image%2020210713164609.png)
`https://bigapp.quoccabank.com/api/v1/bproducts?q=A%27))%20union%20all%20select%20password,email,3,4,5,6%20from%20users;%20--%20garbage`
![Alt](/Images/Pasted%20image%2020210713164642.png)

## Insecure Credential Storage 

**Vulnerability:** Insecure Hash Algorithm for User Credentials

**Severity:** High

**Description:** The backend database stores user passwords as an unsalted MD5 hash - MD5 has been cryptographically unsuitable for over a decade. In the event of a breach (e.g. as a result of the above SQLi vulnerabilities), these credentials will be trivial to crack.

**Remediation:** Salt passwords before commiting their hash to a database (to prevent precomputed dictionary lookup attacks) and adopt a modern crytographic hashing algorithm (e.g. SHA256).

**Asset Domain:** bigapp.quoccabank.com

## Insecure Access Control

**Vulnerability:** Clientside Session Validation via Cookies

**Severity:** Critical

**Description:** The logic for controlling a client's session is dependent upon an insecure clientside cookie. This allows an attacker to authenticate themselves into an administrative session without legitimate credentials. 

**Remediation:** Ideally divorce the session validation and creation logic + data from the client. If this is not possible (i.e. stateless application), utilise existing rigorous frameworks for storing session data on the client, such as JWTs. 

**Asset Domain:** bigapp.quoccabank.com

### Writeup
The `login-cookie` cookie is a base64 encoded string in the format `email:role`, which is trivial to edit and thus allows an attacker to establish an administrative session without credentials. 

![Alt](/Images/Pasted%20image%2020210713164832.png)

i.e. changing the `login-cookie` to `YWRtaW5AcXVvY2NhYmFuay5jb206YWRtaW4=` (`admin@quoccabank.com:admin` base64 encoded). 
![Alt](/Images/Pasted%20image%2020210713164852.png)
