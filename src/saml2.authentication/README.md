[![Build](https://github.com/dina-heidar/saml2-authentication/actions/workflows/builld.yml/badge.svg)](https://github.com/dina-heidar/saml2-authentication/actions/workflows/builld.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/dina-heidar/saml2-authentication/blob/main/LICENSE)
[![Release](https://img.shields.io/github/release/dina-heidar/saml2-authentication.svg)](https://github.com/dina-heidar/saml2-authentication/releases/latest)

SAML2Core Authenticator


<details><summary>About</summary>
<p>

This tool implements the following SAML profiles, message flows and bindings:

<table width="100%" border="1" center>
    <thead>
        <tr>
            <th>Profile</th>
            <th>Message Flows</th>
            <th>Binding</th>
        </tr>
    </thead>
    <tbody> 
        <tr>
            <td rowspan="5">Web SSO</td>
            <td rowspan="3"><code>&lt;AuthnRequest&gt;</code> from SP to IdP</td>
            <td>HTTP Redirect</td>            
        </tr>
        <tr>
            <td>HTTP POST</td>
        </tr>
        <tr>
            <td>HTTP Artifact https://en.wikipedia.org/wiki/SAML_2.0#ArtifactResolveRequest</td>
        </tr>
        <tr>            
            <td rowspan="2">IdP <code>&lt;Response&gt;</code> to SP</td>
            <td>HTTP POST</td>            
        </tr>
        <tr>
            <td>HTTP Artifact</td>
        </tr>
        <tr>
            <td rowspan="8">Single Logout</td>
            <td rowspan="4"><code>&lt;LogoutRequest&gt;</code></td>
            <td>HTTP Redirect</td>            
        </tr>
        <tr>
            <td>HTTP POST</td>
        </tr>
        <tr>
            <td>HTTP Artifact</td>
        </tr>
         <tr>
            <td>SOAP</td>
        </tr>
        <tr>
            <td rowspan="4"><code>&lt;LogoutResponse&gt;</code></td>
            <td>HTTP Redirect</td>       
        </tr>
        <tr>
            <td>HTTP POST</td>
        </tr>
        <tr>
            <td>HTTP Artifact</td>
        </tr>
         <tr>
            <td>SOAP</td>
        </tr>  
        <tr>
            <td rowspan="2">Metadata</td>
            <td >Consumption</td>
            <td></td>                 
        </tr>
        <tr>
            <td>Exchange</td>  
             <td></td>           
        </tr>        
  </tbody>
</table>

</p>
</details>
