# OLSSA
Obfuscated Luau Script Security Auditor by Indirecta  

## Introduction

Welcome to the documentation for OLSSA (Obfuscated Luau Script Security Auditor).  
OLSSA is a security utility designed for Roblox script developers to enhance the security of their games by detecting potential unauthorized behavior
in Roblox models with obfuscated scripts.  

## Table of Contents

-    Overview
-    Installation
-    Configuration
-    Spoofing
-   Sandboxing
-    Protecting Scripts
-    Ethical Considerations

## 1. Overview

OLSSA (Obfuscated Luau Script Security Auditor) is a utility designed to enhance the security of Lua scripts used in Roblox games.  
It aims to prevent potential security vulnerabilities and unauthorized activities by detecting suspicious behavior within scripts.  
## 2. Installation <a name="installation"></a>

To use OLSSA in your Roblox game, follow these steps:

  1.  Copy the code provided in the script you received.
  2.  Paste the code at the top of your Lua script, ensuring it is executed before any other code.
  3.  Customize the configuration settings to meet your security requirements.

## 3. Configuration

OLSSA's behavior can be customized through the configuration settings located at the beginning of the script.  

## 4. Spoofing

OLSSA provides various spoofing mechanisms to alter the behavior of certain services and functions.  
Spoofing can be enabled or disabled for specific services, such as MarketplaceService, RunService, and HttpService.  

## 5. Sandboxing

Sandboxing in OLSSA isolates the results of the require function and certain functions within sandboxed environments. It aims to prevent malicious code from accessing or modifying global variables.

## 6. Protecting Scripts

To protect your scripts from being flagged by OLSSA's security checks, consider the following:

-  Write clean and legitimate code following Roblox's scripting guidelines.
-  Avoid including code that could be misinterpreted as malicious or unauthorized behavior.
-  Use established Roblox services and APIs to minimize the risk of triggering alerts.
-  Regularly review and test your code to identify and address potential vulnerabilities.

## Disclaimer
### User Responsibility

You are responsible for using OLSSA in an ethical and responsible manner.  
OLSSA is intended for educational purposes, it is your own responsibility to respect intellectual property rights, licensing agreements, and the creative efforts of fellow developers.  

### GPL v3 License

OLSSA is released under the GNU General Public License (GPL) version 3. This license provides you with the freedom to study, modify, and distribute the code under certain conditions. Make sure to review and adhere to the GPL v3 license terms when using OLSSA.
