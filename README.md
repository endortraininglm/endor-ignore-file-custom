# endor-ignore-file-custom

A simple Node.js project designed to exercise vulnerability scanners such as Endor Labs.

## Overview

This project intentionally includes a dependency with known security vulnerabilities to test and demonstrate vulnerability scanning capabilities.

## Vulnerable Dependency

- **Package**: lodash
- **Version**: 4.17.19
- **Vulnerability**: CVE-2020-8203 (Prototype Pollution)
- **Category**: String manipulation and object merging
- **CVSS Score**: 7.4 (High)

The vulnerable code paths are exercised through various lodash functions including:
- `_.merge()` - Object merging
- `_.mergeWith()` - Custom object merging
- `_.set()` - Setting nested object properties with string paths
- `_.template()` - String templating
- String manipulation utilities (trim, upperCase, camelCase)

## Installation

```bash
npm install
```

## Usage

Run the application to exercise the vulnerable dependency:

```bash
npm start
```

Or:

```bash
node index.js
```

## Expected Output

The application demonstrates various uses of the vulnerable lodash library, including string manipulation and object operations that could be exploited for prototype pollution attacks.

## Security Warning

⚠️ **This project is for testing purposes only!** 

The included vulnerable dependency (lodash 4.17.19) has known security issues and should not be used in production environments. This project is specifically designed to help test vulnerability scanning tools.

## License

MIT