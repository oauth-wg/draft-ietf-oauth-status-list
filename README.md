# Token Status List

This is the working area for the IETF [OAUTH Working Group](https://datatracker.ietf.org/group/oauth/documents/) Internet-Draft, "Token Status List".

* [Editor's Copy](https://oauth-wg.github.io/draft-ietf-oauth-status-list/#go.draft-ietf-oauth-status-list.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list)
* [Working Group Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list)
* [Compare Editor's Copy to Working Group Draft](https://oauth-wg.github.io/draft-ietf-oauth-status-list/#go.draft-ietf-oauth-status-list.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/oauth-wg/draft-ietf-oauth-status-list/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).


# Implementations

| Project | Language | Issuer | Holder | Relying Party |
|---|---|---|---|---|
| [OWF sd-jwt-js](https://github.com/openwallet-foundation/sd-jwt-js) | TypeScript | yes | yes | yes |

# Testing

You may use this [Cyberchef script](https://gchq.github.io/CyberChef/#recipe=JWT_Decode()JPath_expression('status_list.lst','%5C%5Cn')From_Base64('A-Za-z0-9-_',true,false)Zlib_Inflate(0,0,'Adaptive',false,false)To_Binary('Line%20feed',8)Add_line_numbers()) to quickly analyze a Token Status List in JWT format.