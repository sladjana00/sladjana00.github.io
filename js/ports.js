jQuery(document).ready(function ($) {
    let myObj = {
            "content": [
            {
                "Port": "135",
                "Clients": [
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
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": [
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
            },
            {
                "Port": "3389",
                "Clients": [
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
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": [
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
            },
            {
                "Port": "445",
                "Clients": [
                    {
                        "fqdn": "pam-pc.dmpc.com\r\n",
                        "hostname": "pam-pc.dmpc.com",
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": [
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
            },
            {
                "Port": "8081",
                "Clients": [
                    {
                        "fqdn": "pam-pc.dmpc.com\r\n",
                        "hostname": "pam-pc.dmpc.com",
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": null
            },
            {
                "Port": "139",
                "Clients": [
                    {
                        "fqdn": "pam-pc.dmpc.com\r\n",
                        "hostname": "pam-pc.dmpc.com",
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": [
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
            },
            {
                "Port": "53",
                "Clients": null,
                "Servers": [
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
            },
            {
                "Port": "88",
                "Clients": null,
                "Servers": [
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
            },
            {
                "Port": "389",
                "Clients": [
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
                        "type": "Client",
                        "ip": "10.30.1.13",
                        "computername": "PAM-PC",
                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                        "operatingsystemversion": "10.0 (19041)",
                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                        "tcpports": "445 8081 3389 135 139",
                        "time": "06/04/21 14:08"
                    }
                ],
                "Servers": [
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
            },
            {
                "Port": "5357",
                "Clients": null,
                "Servers": [
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

        let scText = countServersClients(obj);
        let $mainDiv = $("<div data-target-modal='#custom-modal2-"+i+"' class='modal-box ops-item'><p class='ops-number'>" + obj.Port + "</p><span class='os-sc-count'>" + scText + "</span></div>");
        $("#openPorts").append($mainDiv);

        $("body").append(generateModal(obj, i, obj.Port));
    }

    function generateModal(obj, i, opPort) {
        let $modal = $("<div class='custom-modal' id='custom-modal2-" + i + "'>");

        $modal.append("<h3>Open Port" + opPort + "</h3><a href='#' class='close-modal'>Close</a>");

        if(obj.Clients) {
            for (let i = 0; i < obj.Clients.length; i++) {
                let $modalItem = $("<div class='modal-item-wrapper'>");
                let rndID = randomNumber();

                $modalItem.append("<div class='modal-item-heading' data-modal-item-target='#modal-item2-" + rndID + "'>" + generateModalHeading(obj.Clients[i]) + "</div>");
                $modalItem.append("<div class='modal-item-content' id='modal-item2-" + rndID + "'><div class='modal-inner-content'>" + generateModalContent(obj.Clients[i]) + "</div></div>");

                $modal.append($modalItem);
            }
        }

        if(obj.Servers) {
            for (let i = 0; i < obj.Servers.length; i++) {
                let $modalItem = $("<div class='modal-item-wrapper'>");
                let rndID = randomNumber();

                $modalItem.append("<div class='modal-item-heading' data-modal-item-target='#modal-item2-" + rndID + "'>" + generateModalHeading(obj.Servers[i]) + "</div>");
                $modalItem.append("<div class='modal-item-content' id='modal-item2-" + rndID + "'><div class='modal-inner-content'>" + generateModalContent(obj.Servers[i]) + "</div></div>");

                $modal.append($modalItem);
            }
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
    COUNTING CLIENTS AND SERVERS, AND GENERATING TEXT
     */
    function countServersClients(obj) {
        let countClients = 0;
        let countServers = 0;

        if(obj.Clients) {
            countClients = obj.Clients.length;
        }

        if(obj.Servers) {
            countServers = obj.Servers.length;
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
});