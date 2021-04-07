jQuery(document).ready(function ($) {
    let myObj = {
        "content": [
            {
                "OsName": "Windows 10 Enterprise Evaluation",
                "SonsLvl1": [
                    {
                        "fqdn": "JIM-PC.dmpc.com\r\n",
                        "hostname": "jim-pc.dmpc.com",
                        "type": "Client",
                        "ip": "10.30.1.12",
                        "computername": "JIM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=JIM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "",
                        "time": "06/04/21 14:08"
                    },
                    {
                        "fqdn": "MIKE-PC.dmpc.com\r\n",
                        "hostname": "mike-pc.dmpc.com",
                        "type": "Client",
                        "ip": "10.30.1.11",
                        "computername": "MIKE-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=MIKE-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "135 3389",
                        "time": "06/04/21 14:08"
                    },
                    {
                        "fqdn": "pam-pc.dmpc.com\r\n",
                        "hostname": "pam-pc.dmpc.com",
                        "type": "Server",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ]
            },
            {
                "OsName": "Windows Server 2019 Essentials",
                "SonsLvl1": [
                    {
                        "fqdn": "WIN-AD.dmpc.com\r\n",
                        "hostname": "win-ad.dmpc.com",
                        "type": "Server",
                        "ip": "10.10.1.2",
                        "computername": "WIN-AD",
                        "operatingsystem": "Windows Server 2019 Essentials",
                        "operatingsystemversion": "10.0 (17763)",
                        "distinguishedname": "CN=WIN-AD,OU=Domain Controllers,DC=dmpc,DC=com",
                        "tcpports": "53 88 445 389 139 135 5357 3389",
                        "time": "06/04/21 14:08"
                    }
                ]
            }
        ]
    };

    myObj = myObj.content;
    for(let i = 0; i < myObj.length; i++) {
        let obj = myObj[i];

        let scText = countServersClients(obj.SonsLvl1);
        let $mainDiv = $("<div data-target-modal='#custom-modal-"+i+"' class='modal-box os-item " + osTypeClass(obj.OsName) + "'><p class='os-name'>" + obj.OsName + "</p><span class='os-sc-count'>" + scText + "</span></div>");
        $("#operatingSystems").append($mainDiv);

        $("body").append(generateModal(obj.SonsLvl1, i, obj.OsName));
    }

    function generateModal(obj, i, osName) {
        let $modal = $("<div class='custom-modal' id='custom-modal-" + i + "'>");

        $modal.append("<h3>" + osName + "</h3><a href='#' class='close-modal'>Close</a>");

        for(let i = 0; i < obj.length; i++) {
            let $modalItem = $("<div class='modal-item-wrapper'>");
            let rndID = randomNumber();

            $modalItem.append("<div class='modal-item-heading' data-modal-item-target='#modal-item-" + rndID + "'>" + generateModalHeading(obj[i]) + "</div>");
            $modalItem.append("<div class='modal-item-content' id='modal-item-" + rndID + "'><div class='modal-inner-content'>" + generateModalContent(obj[i]) + "</div></div>");

            $modal.append($modalItem);
        }

        return $modal;
    }

    function generateModalHeading(obj) {
        let headingHTML = '';

        if(obj.type === "Client") {
            headingHTML = "<img src='img/client.png'>"
        } else if(obj.type === "Server") {
            headingHTML = "<img src='img/server.png'>"
        }

        headingHTML += "<p>" + obj.ip + "</p>";

        return headingHTML;
    }

    function generateModalContent(obj) {
        let contentHTML = "<p class='resource-ip'><span>IP Address</span><span class='resource-value'>" + obj.ip + "</span></p>";
        contentHTML +=    "<p class='resource-date-time'><span>Date and time</span><span class='resource-value'>01/31/2021 21:42</span></p>";
        contentHTML +=    "<p class='resource-type'><span>Asset type</span><span class='resource-value'>" + obj.type + "</span></p>";
        contentHTML +=    "<p class='resource-name'><span>Asset name</span><span class='resource-value' data-tooltip='" + obj.computername + "'>" + obradi(obj.computername) + "</span></p>";
        contentHTML +=    "<p class='resource-os'><span>OS</span><span class='resource-value' data-tooltip='" + obj.operatingsystem + "'>" + obradi(obj.operatingsystem) + "</span></p>";
        contentHTML +=    "<p class='resource-management'><span>Management</span><span class='resource-value'>Managed</span></p>";
        contentHTML +=    "<p class='resource-tcp-ports'><span>TCP open ports</span><span class='resource-value' data-tooltip='" + obj.tcpports + "'>" + obradi(obj.tcpports) + "</span></p>";

        return contentHTML;
    }


    /*
    GENERATE OS TYPE CLASS FOR BACKGROUND
     */
    function osTypeClass(osName) {
        osName = osName.toLowerCase();

        if(osName.indexOf("windows") !== -1) {
            return "os-item-windows";
        } else if(osName.indexOf("linux") !== -1 ||
                  osName.indexOf("ubuntu") !== -1 ||
                  osName.indexOf("debian") !== -1) {
            return "os-item-linux";
        }

        return "os-item-unknown";
    }

    /*
    COUNTING CLIENTS AND SERVERS, AND GENERATING TEXT
     */
    function countServersClients(obj) {
        let countClients = 0;
        let countServers = 0;
        for(let j = 0; j < obj.length; j++) {
            if(obj[j].type === "Client") {
                countClients++;
            } else if(obj[j].type === "Server") {
                countServers++;
            }
        }

        let scText = "";
        if(countClients > 1) {
            scText += countClients + " Clients";
        } else if(countClients === 1) {
            scText += countClients + " Client";
        }

        if(countServers > 1) {
            if(countClients > 0) {
                scText += ", ";
            }
            scText += countServers + " Servers";
        } else if(countServers === 1) {
            if(countClients > 0) {
                scText += ", ";
            }
            scText += countServers + " Server";
        }

        return scText;
    }

    // If string too long, cut it and add ...
    function obradi(str) {
        if(str.length > 25) {
            str = str.substring(0,23) + "...";
        }

        return str;
    }

    // Generating random number for markup IDs.
    function randomNumber() {
        return Math.floor(Math.random() * 99999) + 11111;
    }

    function replaceAll(str, find, replace) {
        return str.replace(new RegExp(find, 'g'), replace);
    }
});