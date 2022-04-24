## Keycloak auth app

### This repo has everything you need to deploy Keycloak app on heroku

<hr>

#### Usage

you can use the files in keycloak folder. just open your terminal inside this folder and type the following commands:

```bash
heroku container:login
```

```bash
heroku container:push -a {Heroku App name} web
```

```bash
heroku container:release web -a {Heroku App name}
```

-   to be able to use Keycloack in heroku, you must add the free postgres db extension

<hr>

#### Keycloak most important REST endpoints

-   register new user
    -   to be able to register new user, first you need to get the admin token from the master realm

`endpoint: '${HOST}/auth/realms/master/protocol/openid-connect/token'`

`request: simple js fetch request:`

```js
async function getAdminAccessToken() {
    const adminBody = {
        username: 'your admin username',
        password: 'your admin password',
        grant_type: 'password',
        client_id: 'admin-cli',
    };

    try {
        const response = await fetch(ADMIN_TOKEN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },

            /*
            body x-www-form-urlencoded format
             */
            body: new URLSearchParams(adminBody),
        });

        if (!response.ok) {
            throw new Error('Fetching admin token not successful');
        }

        return response.json();
    } catch (e) {
        console.log(e.stackTrace);
    }
}
```

`response:`

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIzYzhTcHZLYl9UenJRZFJqcUxYRy1YR3pFZVc0dTc0cVhJNVVGTFlVZkEwIn0.eyJleHAiOjE2NTA3NDExOTAsImlhdCI6MTY1MDc0MTEzMCwianRpIjoiNDM1NTkyYTQtMzI3ZC00YWM0LTk1ZDUtMTM4MWJkOTg0Yzc4IiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsInN1YiI6IjMwMTA5ZGQ1LTY4YTUtNDJiZi1hOTUyLWRjZThkYmNjYmE3MyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFkbWluLWNsaSIsInNlc3Npb25fc3RhdGUiOiIyYTBjMTE2NC03OGQ0LTRjZDYtOTNmZS0wMzQ1OWU3OTU2MTMiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6MzAwNiJdLCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiIyYTBjMTE2NC03OGQ0LTRjZDYtOTNmZS0wMzQ1OWU3OTU2MTMiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIn0.hUmddMBxhRwTjzBwD80nlpoNGUwPO7KwZKpR9d4AxbbfTvR_iTD0T5huXcWaMRdnmKfXdaITqk8qW7W_mPXdZD1E_tAx5qMZXhLaM3msf43A-nlQnX5G_OKiINhUEmOycybFpOZy3Do63AE8RK0rkOuLJMY8j2rRIb2LrjqPJffSuM3MCk_tzqml3KDDvoUTppKNHYncdtX79fzg8p1fSNJRwApKyp4VEFEhMJZ-CS6LfyHaAFxFoKD0HA0_bZXb0D2OXpDrjVogiykcEMkknYRyXUkmAT7fgdkL-bVboTrIDatfAQ5RorJEQSLdDZ_Zbd1h-ZnS_Bu3okSHUGiQtw",
    "expires_in": 60,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJmMTc4MmRlNi1kOGRlLTRlOWItOGVhNy1mMjNlYjU1YzEzZjIifQ.eyJleHAiOjE2NTA3NDI5MzAsImlhdCI6MTY1MDc0MTEzMCwianRpIjoiZDQ4YmI3NzUtOTgzMy00MWI1LWIxZDUtNTBhNzAyY2MxMWI2IiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6Imh0dHBzOi8vYXBwLWtleWNsb2FrLXByb2QuaGVyb2t1YXBwLmNvbS9hdXRoL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiIzMDEwOWRkNS02OGE1LTQyYmYtYTk1Mi1kY2U4ZGJjY2JhNzMiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiYWRtaW4tY2xpIiwic2Vzc2lvbl9zdGF0ZSI6IjJhMGMxMTY0LTc4ZDQtNGNkNi05M2ZlLTAzNDU5ZTc5NTYxMyIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjJhMGMxMTY0LTc4ZDQtNGNkNi05M2ZlLTAzNDU5ZTc5NTYxMyJ9.8Q0IyC7JYGPEUaFHCPfqZ1pKcwlGXPUOwalUUhGvmsQ",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "2a0c1164-78d4-4cd6-93fe-03459e795613",
    "scope": "profile email"
}
```

<br>

-   once you have the admin access token, you can register new user into your keycloak app.

<br>

`endpoint: '${HOST}/auth/admin/realms/{your realm}/users'`

`request: simple js fetch request:`

```js
async function registerNewUser(firstname, lastname, email, username, password) {
    let adminData = await getAdminAccessToken();

    const newUserData = {
        firstName: firstname,
        lastName: lastname,
        email: email,
        enabled: 'true',
        username: username,
        credentials: [
            {
                type: 'password',
                value: password,
                temporary: false,
            },
        ],
    };

    try {
        const response = await fetch(USER_REGISTER_ENDPOINT, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${adminData.access_token}`,
                'Content-Type': 'application/json',
            },

            body: JSON.stringify(newUserData),
        });

        if (!response.ok) {
            throw new Error('User registration not successful');
        }
    } catch (e) {
        console.log(e.stackTrace);
    }
}
```

`response: status 201`

<br>

-   user login into keycloak app.

<br>

`endpoint: '${HOST}/auth/realms/{your realm}/protocol/openid-connect/token'`

`request: simple js fetch request:`

```js
async function login(username, password) {
    const userLoginData = {
        client_id: 'your client id',
        username: username,
        password: password,
        grant_type: 'password',
    };

    try {
        const response = await fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            /*
            body: again x-www-form-urlencoded format
             */
            body: new URLSearchParams(userLoginData),
        });

        if (!response.ok) {
            throw new Error('Fetching data not successful');
        }

        return response.json();
    } catch (e) {
        console.log(e.stackTrace);
    }
}
```

`response:`

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFSzdra1E0d1VBNVpQOG1YUGsxamZKYUR4Rm5Td0t4T0x2emtkTGp6MTNvIn0.eyJleHAiOjE2NTA3NDI4NjUsImlhdCI6MTY1MDc0MjU2NSwianRpIjoiYTdmOTJlZWItMGJkZS00MzFiLTk3ZGUtZTg5MmY3MDhlMDVlIiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL2h2eiIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJiYTY2MGVhNi00YTAwLTQxODUtODlhMS01NDlmMTQ2ZmJiOTUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJodnotbG9jYWwiLCJzZXNzaW9uX3N0YXRlIjoiMmM0MGI5ZjUtZDVhNy00MmU5LWE3ODYtZGJjOGIwNDgyMmUwIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjMwMDYiLCJodHRwOi8vbG9jYWxob3N0OjUwMDEiLCIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtaHZ6IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiIyYzQwYjlmNS1kNWE3LTQyZTktYTc4Ni1kYmM4YjA0ODIyZTAiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJUZXN0dXNlcjIgVGVzdHVzZXIyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIyIiwiZ2l2ZW5fbmFtZSI6IlRlc3R1c2VyMiIsImZhbWlseV9uYW1lIjoiVGVzdHVzZXIyIiwiZW1haWwiOiJ0ZXN0dXNlcjJAdGVzdC5jb20ifQ.IXfEnbADfBsldWYm8Tf8OX7y93hsSW9lRaYZwUc-slUN69Z1qeUdxNe_46SzjKapDvCKQQ7sFS1Kf30Wv8HTNufA9-eARpow2Z-R3hezC3va8ktCE545OAQUBR07ex9DWKYq1hpz2LX2fRaTsgDH7XhDqVVutcLkKqayRxM-XqpJbEye8jn2h6CN6npFL4C7eI5llrj7tsvryojBzdNMYwKo5BVYt1_8CIkVvWK3GWMVjjftzAHFyKNyhOVD1LS12IouxSw7Y3INqlxBD1ptXNB8qQTWQlon4Q5zDe8YGYgoC77FKakInDvd11iXgs400TThHukrIgJTGJI8kc74sw",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwMjk2ZDJiMS05MmYyLTQwMjUtODc1My04MGEzMDE1YWFiOGMifQ.eyJleHAiOjE2NTA3NDQzNjUsImlhdCI6MTY1MDc0MjU2NSwianRpIjoiOTdmZmY1NjItNTdkZi00Yzg1LTk2ZmItMWNkMTcwMGM3YmQ4IiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL2h2eiIsImF1ZCI6Imh0dHBzOi8vYXBwLWtleWNsb2FrLXByb2QuaGVyb2t1YXBwLmNvbS9hdXRoL3JlYWxtcy9odnoiLCJzdWIiOiJiYTY2MGVhNi00YTAwLTQxODUtODlhMS01NDlmMTQ2ZmJiOTUiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiaHZ6LWxvY2FsIiwic2Vzc2lvbl9zdGF0ZSI6IjJjNDBiOWY1LWQ1YTctNDJlOS1hNzg2LWRiYzhiMDQ4MjJlMCIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjJjNDBiOWY1LWQ1YTctNDJlOS1hNzg2LWRiYzhiMDQ4MjJlMCJ9.PvqCfi-3m2YfxWladAwW9G3DguAvNeufKtdATATFwCQ",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "2c40b9f5-d5a7-42e9-a786-dbc8b04822e0",
    "scope": "profile email"
}
```

<br>

-   after the user access token has expired, you can refresh it:

<br>

`endpoint: '${HOST}/auth/realms/{your realm}/protocol/openid-connect/token'`

`request: simple js fetch request:`

```js
async function refreshUserAccessToken(refresh_token) {
    const userLoginData = {
        client_id: 'your client id',
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
    };

    let responseUserData;

    try {
        const response = await fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },

            /*
            body: x-www-form-urlencoded format
             */
            body: new URLSearchParams(userLoginData),
        });

        if (!response.ok) {
            throw new Error('Fetching data not successful');
        }

        return response.json();
    } catch (e) {
        console.log(e.stackTrace);
    }
}
```

`response:`

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFSzdra1E0d1VBNVpQOG1YUGsxamZKYUR4Rm5Td0t4T0x2emtkTGp6MTNvIn0.eyJleHAiOjE2NTA3NDI4NjUsImlhdCI6MTY1MDc0MjU2NSwianRpIjoiYTdmOTJlZWItMGJkZS00MzFiLTk3ZGUtZTg5MmY3MDhlMDVlIiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL2h2eiIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJiYTY2MGVhNi00YTAwLTQxODUtODlhMS01NDlmMTQ2ZmJiOTUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJodnotbG9jYWwiLCJzZXNzaW9uX3N0YXRlIjoiMmM0MGI5ZjUtZDVhNy00MmU5LWE3ODYtZGJjOGIwNDgyMmUwIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjMwMDYiLCJodHRwOi8vbG9jYWxob3N0OjUwMDEiLCIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtaHZ6IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiIyYzQwYjlmNS1kNWE3LTQyZTktYTc4Ni1kYmM4YjA0ODIyZTAiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJUZXN0dXNlcjIgVGVzdHVzZXIyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIyIiwiZ2l2ZW5fbmFtZSI6IlRlc3R1c2VyMiIsImZhbWlseV9uYW1lIjoiVGVzdHVzZXIyIiwiZW1haWwiOiJ0ZXN0dXNlcjJAdGVzdC5jb20ifQ.IXfEnbADfBsldWYm8Tf8OX7y93hsSW9lRaYZwUc-slUN69Z1qeUdxNe_46SzjKapDvCKQQ7sFS1Kf30Wv8HTNufA9-eARpow2Z-R3hezC3va8ktCE545OAQUBR07ex9DWKYq1hpz2LX2fRaTsgDH7XhDqVVutcLkKqayRxM-XqpJbEye8jn2h6CN6npFL4C7eI5llrj7tsvryojBzdNMYwKo5BVYt1_8CIkVvWK3GWMVjjftzAHFyKNyhOVD1LS12IouxSw7Y3INqlxBD1ptXNB8qQTWQlon4Q5zDe8YGYgoC77FKakInDvd11iXgs400TThHukrIgJTGJI8kc74sw",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwMjk2ZDJiMS05MmYyLTQwMjUtODc1My04MGEzMDE1YWFiOGMifQ.eyJleHAiOjE2NTA3NDQzNjUsImlhdCI6MTY1MDc0MjU2NSwianRpIjoiOTdmZmY1NjItNTdkZi00Yzg1LTk2ZmItMWNkMTcwMGM3YmQ4IiwiaXNzIjoiaHR0cHM6Ly9hcHAta2V5Y2xvYWstcHJvZC5oZXJva3VhcHAuY29tL2F1dGgvcmVhbG1zL2h2eiIsImF1ZCI6Imh0dHBzOi8vYXBwLWtleWNsb2FrLXByb2QuaGVyb2t1YXBwLmNvbS9hdXRoL3JlYWxtcy9odnoiLCJzdWIiOiJiYTY2MGVhNi00YTAwLTQxODUtODlhMS01NDlmMTQ2ZmJiOTUiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiaHZ6LWxvY2FsIiwic2Vzc2lvbl9zdGF0ZSI6IjJjNDBiOWY1LWQ1YTctNDJlOS1hNzg2LWRiYzhiMDQ4MjJlMCIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjJjNDBiOWY1LWQ1YTctNDJlOS1hNzg2LWRiYzhiMDQ4MjJlMCJ9.PvqCfi-3m2YfxWladAwW9G3DguAvNeufKtdATATFwCQ",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "2c40b9f5-d5a7-42e9-a786-dbc8b04822e0",
    "scope": "profile email"
}
```
<br>
<hr>

#### Java: Spring Security integration

-   application.properties

```
  spring.security.oauth2.resourceserver.jwt.issuer-uri=${ISSUER_URL:{your keycloak host}/auth/realms/hvz}
  spring.security.oauth2.resourceserver.jwt.jwk-set-uri=${JWKS_URI:{your keycloak host}/auth/realms/hvz/protocol/openid-connect/certs}
```

-   Security config

```java

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;


import java.util.Collection;
import java.util.HashSet;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // Enable CORS -- this is further configured on the controllers
                .cors().and()

                // Sessions will not be used
                .sessionManagement().disable()

                // Disable CSRF -- not necessary when there are sessions
                .csrf().disable()

                // Enable security for http requests
                .authorizeRequests(authorize -> {
                    authorize
                            // Specify paths where public access is allowed
                            .antMatchers("/.well-known/oas/**")
                            .permitAll()
                            .antMatchers("/swagger-ui/**")
                            .permitAll()
                            .antMatchers(HttpMethod.GET, "/api/game")
                            .permitAll()
                            .antMatchers(HttpMethod.GET, "/api/player")
                            .permitAll()
                            .antMatchers(HttpMethod.GET, "/api/user")
                            .permitAll()
                            .antMatchers("/ws/**")
                            .permitAll()
                            // All remaining paths require authentication
                            .anyRequest().authenticated();
                })

                // Configure OAuth2 Resource Server (JWT authentication)
                .oauth2ResourceServer(oauth2 -> {
                    // Convert Jwt to AbstractAuthenticationToken
                    JwtAuthenticationConverter authnConverter = new JwtAuthenticationConverter();

                    // Convert Jwt scopes claim to GrantedAuthorities
                    JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();

                    // Convert Jwt groups claim to GrantedAuthorities
                    JwtGrantedAuthoritiesConverter groupConverter = new JwtGrantedAuthoritiesConverter();
                    groupConverter.setAuthorityPrefix("GROUP_");
                    groupConverter.setAuthoritiesClaimName("groups");

                    // Convert Jwt roles claim to GrantedAuthorities
                    JwtGrantedAuthoritiesConverter roleConverter = new JwtGrantedAuthoritiesConverter();
                    roleConverter.setAuthorityPrefix("ROLE_");
                    roleConverter.setAuthoritiesClaimName("roles");

                    // Jwt -> GrantedAuthorities -> AbstractAuthenticationToken
                    authnConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
                        // This will read the 'scope' claim inside the payload
                        Collection<GrantedAuthority> scopes = scopeConverter.convert(jwt);

                        // This will read the 'roles' claim you configured above
                        // jwt["roles"] -> new GrantedAuthority("ROLE_roleName")
                        Collection<GrantedAuthority> roles = roleConverter.convert(jwt);

                        // This will read the 'groups' claim you configured above
                        // jwt["groups"] -> new GrantedAuthority("GROUP_groupName")
                        Collection<GrantedAuthority> groups = groupConverter.convert(jwt);

                        // Merge the above sets
                        HashSet<GrantedAuthority> union = new HashSet<>();
                        union.addAll(scopes);
                        union.addAll(roles);
                        union.addAll(groups);

                        for (var a : union) {
                            logger.warn("JWT Authority: {}", a.getAuthority());
                        }

                        return union;
                    });

                    // Enable JWT authentication and access control from JWT claims
                    oauth2.jwt().jwtAuthenticationConverter(authnConverter);
                });

    }
}

```

-   Method Security Config

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
}
```

<hr>
<br>

## Maintainer

[Petar Dimitrov]


## License

[MIT]
---

[Petar Dimitrov]: https://github.com/PetarDimitrov91
[MIT]: https://choosealicense.com/licenses/mit/
