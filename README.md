Authentication and authorization
===========================

Keycloak server
----------------------

This will be a quick introduction to the main concepts of Keycloak Authorization services. For better understanding please refer to the [official documentation](https://www.keycloak.org/docs/latest/authorization_services/index.html).

### Defining clients and their roles

First of all, there must be one client associated to the frontend and another one associated to the backend. The two will share roles and authorization tokens, but remains separate entities; typically, on UI side the permission are simply used to hide/show page elements where on the backend they are actually enforced resulting in an error when the request is unauthorized. Here we take as example the two clients of the UNM application

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-7_17-38-28.png?version=1&modificationDate=1565192308748&api=v2)

The following configuration has been setup on both clients in order to use Keycloak Authorization services:

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-7_17-42-14.png?version=1&modificationDate=1565192534734&api=v2)

-   Confidential access type allows to use ring uthentication between frontend     and backend

-   Credentials are normally set to use *ClientId and Secret*.

-   Enabling authorization will therefore show the Authorization tab.

It is also important to define some client roles: on backend client, those should be aliases of the frontend client roles: it's possible to do so thanks to role composition. UNM defines as roles on unm-api client the aliases of the unm-ui client roles.

**NOTE: when exporting authorization settings, the client roles are not included and must be recreated manually on the target platform**

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-7_17-52-48.png?version=1&modificationDate=1565193169025&api=v2)

Then, we create resources. Resources define, along with a name, a type and an URL, several scopes and associated permissions.

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-7_18-1-1.png?version=1&modificationDate=1565193661595&api=v2)

It means that scopes may define what are the possible operations available on a given resource (eg: resource User, scopes C/R/U/D) but a fine grained permission control will associate to each user role the  appropriate scopes, as shown
below:

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-7_18-7-56.png?version=1&modificationDate=1565194076420&api=v2)

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-8_11-13-20.png?version=1&modificationDate=1565255600992&api=v2)

There we see that the *support* role can only **read** configuration (among other read scopes) while *exploitation* role can **update** it. In order to make things work, role composition must be done so that *exploitation* role is composed by *support* role: by doing so we ensure that *exploitation* role can both read and update, without explicitly giving the read permission scope.

There is a tool that allows to verify that authorization is setup correctly by evaluating the rules. Here below we indeed see that a *support* role cannot update configuration while an *exploitation* role can read it.

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-8_10-27-0.png?version=1&modificationDate=1565252821011&api=v2)

![enter image description here](https://confluence.itsf.io/download/attachments/12813312/image2019-8-8_10-27-50.png?version=1&modificationDate=1565252870518&api=v2)

Lastly, the Export Settings tab allows to export the whole setup in json format.

**NOTE: after exporting authorization settings, edit the produced json to remove all id and _id fields; this will allow to import such settings on a different platform than the one the settings were done onto, appropriately creating or
updating them.**

Java auth-lib for API client
======================

In all different java microservices there is the need to handle altogether the following points:

-   HTTP/Websocket Session management

-   Authentication and Security

-   Authorization

Therefore a library contains all the necessary spring autoconfiguration code to work well with keycloak and cover the previous points.

<https://gitlab.mt.lan/it-factory/auth-lib>

### HTTP/Websocket session management

The session opened for an HTTP request is not the same as the one opened for a websocket request, but it is desirable to recognize that the two request came from the same client and unify the two sessions.

The library configures an handshake and channel interceptor  in order to insert the HttpSession id inside the connection attributes. The same id is recovered from the incoming messages inside the inbound channel in order to retrieve from the sessionRepository the same session that was initiated by the HTTP request

[source](https://docs.spring.io/spring-session/docs/current/api/org/springframework/session/web/socket/server/SessionRepositoryMessageInterceptor.html)

### Authentication

The library will use keycloak for authentication. Therefore, the necessary configuration is done conditionally whether a bean annotated with `@KeycloakConfiguration` is missing.

A basic spring security configuration including keycloak authentication and CORS is provided. You can extend [KeycloakSecurityConfiguration](https://gitlab.mt.lan/it-factory/auth-lib/blob/master/src/main/java/mc/monacotelecom/auth/config/KeycloakSecurityConfiguration.java) and override the needed methods if a finer tuning is needed.

[source](https://www.keycloak.org/docs/latest/securing_apps/index.html#_spring_security_adapter)

### Authorization

The library provides a [PermissionEvaluator](https://gitlab.mt.lan/it-factory/auth-lib/blob/master/src/main/java/mc/monacotelecom/auth/config/support/KeycloakScopePermissionEvaluator.java) that uses keycloak authorization underneath. This makes it easier to use spring security authorization annotations as in the following example:

**Example of keycloak preauthorization**

    @PreAuthorize("hasPermission([resourceName], [scopeName])")

[source](https://www.baeldung.com/spring-security-create-new-custom-security-expression)

According to the evaluator implementation it is possible to pass an empty string ("") as [resourceName]: this has the effect of verifying the presence of a given scope regardless of the resource being accessed, and works more generally than adding unrelated scopes to a given permission (like it was done in *configuration_support* image above). It proves to be useful where an API needs to access several resources behind the scenes, despite of the initial one accessed by the client API invocation; as an example, consider that a configuration read operation also need to read models or instances (which are different resources): in this case it's possible to omit the resource name otherwise the evaluation may fail.

In fact, the kind of resource being accessed is determined by the URL of the API invocation; therefore if the client is calling */dictionaries/system* the resource is identified as configuration (because this resource is matching URL patterns like */dictionaries/**) and as soon as the configuration_read operation will need to call a method annotated with
`@PreAuthorize("hasPermission('models', 'models_read')")` it will fail since model resource is not resolved by this call. However, annotating the same method with `@PreAuthorize("hasPermission('', 'models_read')")` would make this scenario work
correctly

### Installation for stateful usage

The library is installed as a maven dependency; also, make sure to cover all the transitive dependencies marked as provided in the library pom.xml

**Maven dependencies in pom.xml for a stateful configuration using WebSocket**

    <dependencies>
		<dependency>
			<groupId>mc.monacotelecom.auth</groupId>
			<artifactId>auth-lib</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-websocket</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.session</groupId>
			<artifactId>spring-session-core</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-messaging</artifactId>
		</dependency>
    </dependencies>
    
As illustrated above you will need to explicitely reference spring-messaging
dependency if you want to actually send message to the websockets by mean of a
SimpMessageSendingOperations template.    

You can create a CorsConfigurationSource bean inside one of your @Configuration
classes; it will be used for spring security configuration.

**Cors configuration source**

	@Bean
	@Primary
	public CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		final org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();

		config.setAllowCredentials(true);
		config.setAllowedOrigins(Collections.singletonList("*"));
		config.setAllowedHeaders(Arrays.asList("Origin", "Content-Type", "Accept"));

		config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));

		source.registerCorsConfiguration("/**", config);
		return source;
	}

Finally, keycloak configuration is done inside the application.yml file. We instruct the policy enforcer not to control the actuator path (which will be accessible to anybody) and the websocket broker endpoint (it is */messages* by default but can be changed by the autoconfiguration property *messaging.broker.endpoint*). The latter is actually controlled by the channel interceptor that the library defines.

**application.yml**

    spring:
      main:
        allow-bean-definition-overriding: true
     
    keycloak:
      auth-server-url: https://iam.prod.lan/auth
      credentials:
        secret: ba880d10-7527-46a2-9d79-0355875815e4
      realm: monaco-telecom-local
      resource: unm-api
      ssl-required: external
      use-resource-role-mappings: true
      principal-attribute: preferred_username
      policy-enforcer-config:
        enforcement-mode: ENFORCING
        paths:
          - path: /actuator/*
            enforcement-mode: DISABLED
          - path: /messages/*
            enforcement-mode: DISABLED
      cors: true
      securityConstraints:
        - authRoles:
          securityCollections:
            - patterns:
                - /actuator/*
            - patterns:
                - /messages/*
        - authRoles:
            - administration
            - exploitation
            - support
          securityCollections:
            - patterns:
                - /*
    logging:
      level:
        org:
          keycloak: TRACE
          apache.catalina.realm: TRACE

### Installation for stateless usage

The library is installed as a maven dependency; also, make sure to cover all the transitive dependencies marked as provided in the library pom.xml

**Maven dependencies in pom.xml for a stateless configuration**

    <dependencies>
		<dependency>
			<groupId>mc.monacotelecom.auth</groupId>
			<artifactId>auth-lib</artifactId>
		</dependency>
	    <dependency>
    		<groupId>org.springframework.boot</groupId>
    		<artifactId>spring-boot-starter-security</artifactId>
    	</dependency>
    </dependencies>
    
You can create a CorsConfigurationSource bean inside one of your @Configuration
classes; it will be used for spring security configuration.

**Cors configuration source**

	@Bean
	@Primary
	public CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		final org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();

		config.setAllowCredentials(true);
		config.setAllowedOrigins(Collections.singletonList("*"));
		config.setAllowedHeaders(Arrays.asList("Origin", "Content-Type", "Accept"));

		config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));

		source.registerCorsConfiguration("/**", config);
		return source;
	}

Finally, keycloak configuration is done inside the application.yml file. We instruct the policy enforcer not to control the actuator path (which will be accessible to anybody).

**application.yml**

    spring:
      main:
        allow-bean-definition-overriding: true
     
    keycloak:
      auth-server-url: https://iam.prod.lan/auth
      credentials:
        secret: ba880d10-7527-46a2-9d79-0355875815e4
      realm: monaco-telecom-local
      resource: unm-api
      ssl-required: external
      use-resource-role-mappings: true
      principal-attribute: preferred_username
      policy-enforcer-config:
        enforcement-mode: ENFORCING
        paths:
          - path: /actuator/*
            enforcement-mode: DISABLED
      cors: true
      securityConstraints:
        - authRoles:
          securityCollections:
            - patterns:
                - /actuator/*
        - authRoles:
            - administration
            - exploitation
            - support
          securityCollections:
            - patterns:
                - /*
    logging:
      level:
        org:
          keycloak: TRACE
          apache.catalina.realm: TRACE

### Allowing browser or bearer only access

The library supports both token access and browser access using cookies, always having keycloak configuration set for a *confidential* access type as pictured above. However, inside kubernates and behind Ingress, the router will no longer be able to redirect to the login URI since the URI /sso/login is not associated to any route. To fix this issue, it is possible to add an additional property to the application.yml to make sure that the login URI is correctly interpreted by the Ingress router.

If, for instance the application URI matched by Ingress is /myapplication then the following setting is needed for the browser login to work as expected:

**Override login URI behind Ingress**

    sso.login-uri: /myapplication/login

On the other hand, if there is the need to configure the application for bearer
only access, simply add the following line to the application.yml file instead
of the line above:

**Set the application for bearer only access**

    keycloak.bearer-only: true

Javascript integration for UI client
============================

This section is a side note. Please refer to the [Javascript integration](https://www.keycloak.org/docs/latest/authorization_services/index.html#_enforcer_js_adapter) official documentation for a deeper understanding.

The available permission scopes are present in the Javascript Web Token returned by a call to keycloak javascript adapter entitlement() method; Once the token is
decoded we can store the authorizations (in a global variable, local storage or redux state) and *make effective use of the scopes regardless of the rules evaluation that produced them*, keeping the client code tidy. In the code below the keycloak object is also monkey-patched to add the list of authorizations and a function called authorize() enabling to perform authorized calls to the API.

**Keycloak entitlement**

    authorization.entitlement(keycloakConfig.clientId, {
            permissions: [
            'menu', 'import', 'locations', 'containers', 'cables', 'equipments', 'accesses'
        ].map(p =>  { return { id : p } })
    }).then(rpt => {
        keycloak.authorizations = {}
        jwt.decode(rpt).authorization.permissions
            .map(p => p.scopes)
            .reduce((acc, val) => acc.concat(val), [])
            .forEach(p => keycloak.authorizations[p] = true)
     
        keycloak.authorize = (additionalConfig = {}) => {
            let authorized = Object.assign(additionalConfig, {
                credentials: 'include'
            })
            authorized.headers = Object.assign(additionalConfig.headers || {}, {
                'Authorization': 'Bearer ' + keycloak.token
            })
            return authorized
        }
    })

It is now easy to check for permission or make an authorized call, like in the
following example:

**Usage of permission scopes and authorizations**

    if (keycloak.authorizations["configuration_read"]) {
        fetch('/dictionaries/system', keycloak.authorize())
        .then(response => {
            ...
        })
        .catch(error => ...)
    }

Troubleshooting
============================

**Websocket can't connect**

Be sure that the `CorsConfigurationSource` is loaded before auth-lib; if it is not the case you will have `Invalid CORS Request` as response to the websocket connection attempt.

In order to force the bean to load first, you can add the configuration class (`CorsSecurityConfiguration`) that defines it to the application primary source

    SpringApplication.run(new Class[] {MyApplication.class, CorsSecurityConfiguration.class}, args);