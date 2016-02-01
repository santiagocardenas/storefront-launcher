# Citrix Solutions Lab StoreFront Launcher Script
Launch HDX session to a published resource through StoreFront or NetScaler Gateway (integrated with StoreFront)

## Original Blog Posts
https://www.citrix.com/blogs/2013/11/27/scripting-automating-the-launch-of-hdx-sessions-through-storefront-and-netscaler-gateway-integrated-with-storefront/

https://www.citrix.com/blogs/2014/06/12/scripting-update-automating-the-launch-of-hdx-sessions-through-storefront-and-netscaler-gateway-integrated-with-storefront/

## Description
This script launches an HDX session to a published resource through StoreFront or NetScaler Gateway (integrated with StoreFront).

It attempts to closely resemble what an actual user would do by:
* Opening Internet Explorer.
* Navigating directly to the Receiver for Web site or NetScaler Gateway portal.
* Completing the fields.
* Logging in.
* Clicking on the resource.
* Logging off the StoreFront site.       

## Requirements:
* Use an Administrator console of PowerShell.
* SiteURL should be part of the Intranet Zone (or Internet Zone at Medium-Low security) in order to be able to download AND launch the ICA file. This can be done through a GPO.
* StoreFront 2.0 or higher.
* If using NetScaler Gateway, version 9.3 or higher.
* Changes in web.config under C:\inetpub\wwwroot\Citrix\<storename>Web\: autoLaunchDesktop to false, pluginAssistant to false and logoffAction to none.
* Currently works for desktops or already subscribed apps only. You can auto subscribe users to apps by setting "KEYWORDS:Auto" in the published app's description.


### Disclaimer:
*This software / sample code is provided to you “AS IS” with no representations, warranties or conditions of any kind. You may use, modify and distribute it at your own risk. CITRIX DISCLAIMS ALL WARRANTIES WHATSOEVER, EXPRESS, IMPLIED, WRITTEN, ORAL OR STATUTORY, INCLUDING WITHOUT LIMITATION WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NONINFRINGEMENT. Without limiting the generality of the foregoing, you acknowledge and agree that (a) the software / sample code may exhibit errors, design flaws or other problems, possibly resulting in loss of data or damage to property; (b) it may not be possible to make the software / sample code fully functional; and (c) Citrix may, without notice or liability to you, cease to make available the current version and/or any future versions of the software / sample code. In no event should the software / code be used to support of ultra-hazardous activities, including but not limited to life support or blasting activities. NEITHER CITRIX NOR ITS AFFILIATES OR AGENTS WILL BE LIABLE, UNDER BREACH OF CONTRACT OR ANY OTHER THEORY OF LIABILITY, FOR ANY DAMAGES WHATSOEVER ARISING FROM USE OF THE SOFTWARE / SAMPLE CODE, INCLUDING WITHOUT LIMITATION DIRECT, SPECIAL, INCIDENTAL, PUNITIVE, CONSEQUENTIAL OR OTHER DAMAGES, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. You agree to indemnify and defend Citrix against any and all claims arising from your use, modification or distribution of the code.*
