jQuery(document).ready(function () {
    $(".all-tabs a").click(function (e) {
        e.preventDefault();

        $(".all-tabs a").removeClass('active');
        $(this).addClass('active');
        let cID = $(this).attr('data-target');

        $(".content-item").hide();
        $(cID).slideDown();
    });

    $(document).on("click", ".accordion-item-content .accordion-item, .accordion > .accordion-item", function (e) {
        e.preventDefault();

        let cID = $(this).attr('data-target');

        $(this).toggleClass('active');

        $("[data-expand='"+ cID +"']").slideToggle();
    });



    // Populate this object with JSON data.
    let myObj = {
        "content": [
            {
                "ip_lvl1": "10.*.*.*",
                "SonsLvl1": [
                    {
                        "ip_lvl2": "10.10.*.*",
                        "sons_lev_2": [
                            {
                                "ip_lvl3": "10.10.1.*",
                                "clients": null,
                                "servers": [
                                    {
                                        "fqdn": "WIN-AD.dmpc.com\r\n",
                                        "hostname": "win-ad.dmpc.com",
                                        "type": "Server",
                                        "ip": "10.10.1.2",
                                        "computername": "WIN-AD",
                                        "operatingsystem": "Windows Server 2019 Essentials",
                                        "distinguishedname": "CN=WIN-AD,OU=Domain Controllers,DC=dmpc,DC=com",
                                        "tcpports": "389 139 135 88 53 3389 445 5357"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "ip_lvl2": "10.30.*.*",
                        "sons_lev_2": [
                            {
                                "ip_lvl3": "10.30.1.*",
                                "clients": [
                                    {
                                        "fqdn": "JIM-PC.dmpc.com\r\n",
                                        "hostname": "jim-pc.dmpc.com",
                                        "type": "Client",
                                        "ip": "10.30.1.12",
                                        "computername": "JIM-PC",
                                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                                        "distinguishedname": "CN=JIM-PC,CN=Computers,DC=dmpc,DC=com",
                                        "tcpports": ""
                                    },
                                    {
                                        "fqdn": "MIKE-PC.dmpc.com\r\n",
                                        "hostname": "mike-pc.dmpc.com",
                                        "type": "Client",
                                        "ip": "10.30.1.11",
                                        "computername": "MIKE-PC",
                                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                                        "distinguishedname": "CN=MIKE-PC,CN=Computers,DC=dmpc,DC=com",
                                        "tcpports": ""
                                    }
                                ],
                                "servers": null
                            }
                        ]
                    }
                ]
            },
            {
                "ip_lvl1": "fe80:*:*:*",
                "SonsLvl1": [
                    {
                        "ip_lvl2": "fe80:e5dc:*:*",
                        "sons_lev_2": [
                            {
                                "ip_lvl3": "fe80:e5dc:312f:*",
                                "clients": [
                                    {
                                        "fqdn": "pam-pc.dmpc.com\r\n",
                                        "hostname": "pam-pc.dmpc.com",
                                        "type": "Client",
                                        "ip": "fe80::e5dc:312f:5295",
                                        "computername": "PAM-PC",
                                        "operatingsystem": "Windows 10 Enterprise Evaluation",
                                        "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                                        "tcpports": "445 135 8081 3389 139"
                                    }
                                ],
                                "servers": null
                            }
                        ]
                    }
                ]
            }
        ]
    }

    myObj = myObj.content;

    // Counters for Labels (Mixed/Server/Client IPs and Assets)
    let countServers = 0;
    let countClients = 0;

    for(let i = 0; i < myObj.length; i++) {
        let obj = myObj[i];

        // Creating Layer X inside main group.
        let $itemHeading = $("<div class='accordion-item' data-target='accordion-expand-content"+i+"-2'>");
        let $itemContent = $("<div class='accordion-item-content' data-expand='accordion-expand-content"+i+"-2'>");

        let outServerCounter = 0;
        let outClientCounter = 0;

        // Here goes a loop.
        for(let j = 0; j < obj.SonsLvl1.length; j++) {
            let inObj = obj.SonsLvl1[j];
            let rndID = randomNumber();

            let $innerItemHeading = $("<div class='accordion-item' data-target='accordion-expand-content"+i+"-"+rndID+"'>");
            let $innerItemContent = $("<div class='accordion-item-content' data-expand='accordion-expand-content"+i+"-"+rndID+"'>");

            let outsideServerCounter = 0;
            let outsideClientCounter = 0;

            // Here goes a loop.
            for(let k = 0; k < inObj.sons_lev_2.length; k++) {
                let inInObj = inObj.sons_lev_2[k];
                let rndID = randomNumber();

                let $innerInnerItemHeading = $("<div class='accordion-item' data-target='accordion-expand-content"+i+"-"+rndID+"'>");
                let $innerInnerItemContent = $("<div class='accordion-item-content' data-expand='accordion-expand-content"+i+"-"+rndID+"'>");


                $innerInnerItemContent.append("<div class='accordion-item-resource'>");
                let $populateRow = $innerInnerItemContent.find(".accordion-item-resource");

                $populateRow.append("<p class='resource-ip'><span>IP Address</span></p>");
                $populateRow.append("<p class='resource-date-time'><span>Date and time</span></p>");
                $populateRow.append("<p class='resource-type'><span>Asset type</span></p>");
                $populateRow.append("<p class='resource-name'><span>Asset name</span></p>");
                $populateRow.append("<p class='resource-os'><span>OS</span></p>");
                $populateRow.append("<p class='resource-management'><span>Management</span></p>");
                $populateRow.append("<p class='resource-tcp-ports'><span>TCP open ports</span></p>");
                $populateRow.append("<p class='resource-udp-ports'><span>UDP open ports</span></p>");


                let innerServerCounter = 0;
                let innerClientCounter = 0;

                // Here goes a loop for servers.
                if(inInObj.servers) {
                    for (let l = 0; l < inInObj.servers.length; l++) {
                        let csObj = inInObj.servers[l];

                        $populateRow.find(".resource-ip").append("<span class='resource-value'>" + csObj.ip + "</span>");
                        $populateRow.find(".resource-date-time").append("<span class='resource-value'>01/31/2021 21:42</span>");
                        $populateRow.find(".resource-type").append("<span class='resource-value'>Server</span>");
                        $populateRow.find(".resource-name").append("<span class='resource-value'>" + obradi(csObj.computername) + "</span>");
                        $populateRow.find(".resource-os").append("<span class='resource-value'>" + obradi(csObj.operatingsystem) + "</span>");
                        $populateRow.find(".resource-management").append("<span class='resource-value'>Managed</span>");
                        $populateRow.find(".resource-tcp-ports").append("<span class='resource-value'>" + obradi(csObj.tcpports) + "</span>");
                        $populateRow.find(".resource-udp-ports").append("<span class='resource-value'>N/A</span>");

                        // Counting servers.
                        countServers++;
                        innerServerCounter++;
                        outsideServerCounter++;
                        outServerCounter++;
                    }
                }

                // Here goes a loop for clients.
                if(inInObj.clients) {
                    for (let l = 0; l < inInObj.clients.length; l++) {
                        let csObj = inInObj.clients[l];

                        $populateRow.find(".resource-ip").append("<span class='resource-value'>" + csObj.ip + "</span>");
                        $populateRow.find(".resource-date-time").append("<span class='resource-value'>01/31/2021 21:42</span>");
                        $populateRow.find(".resource-type").append("<span class='resource-value'>Client</span>");
                        $populateRow.find(".resource-name").append("<span class='resource-value'>" + obradi(csObj.computername) + "</span>");
                        $populateRow.find(".resource-os").append("<span class='resource-value'>" + obradi(csObj.operatingsystem) + "</span>");
                        $populateRow.find(".resource-management").append("<span class='resource-value'>Managed</span>");
                        $populateRow.find(".resource-tcp-ports").append("<span class='resource-value'>" + obradi(csObj.tcpports) + "</span>");
                        $populateRow.find(".resource-udp-ports").append("<span class='resource-value'>N/A</span>");

                        // Counting Clients.
                        countClients++;
                        innerClientCounter++;
                        outsideClientCounter++;
                        outClientCounter++;
                    }
                }

                let hText = "";
                let hImg = "img/client.png";

                if(innerClientCounter > 0) {
                    hText += innerClientCounter + " Client Asset"

                    if(innerClientCounter > 1) {
                        hText += "s";
                    }
                }

                if(innerServerCounter > 0) {
                    if(innerClientCounter > 0) {
                        hText += ", ";
                        hImg = "img/half.png";
                    } else {
                        hImg = "img/server.png";
                    }

                    hText += innerServerCounter + " Server Asset"

                    if(innerServerCounter > 1) {
                        hText += "s";
                    }
                }

                $innerInnerItemHeading.append($("<img src='" + hImg + "'>"));
                $innerInnerItemHeading.append($("<p><span class='ip-range'>" + inInObj.ip_lvl3 + "</span>" + hText + "</p>"));

                $innerItemContent.append($innerInnerItemHeading);
                $innerItemContent.append($innerInnerItemContent);
            }


            let hText = "";
            let hImg = "img/client.png";

            if(outsideClientCounter > 0) {
                hText += outsideClientCounter + " Client Asset"

                if(outsideClientCounter > 1) {
                    hText += "s";
                }
            }

            if(outsideServerCounter > 0) {
                if(outsideClientCounter > 0) {
                    hText += ", ";
                    hImg = "img/half.png";
                } else {
                    hImg = "img/server.png";
                }

                hText += outsideServerCounter + " Server Asset"

                if(outsideServerCounter > 1) {
                    hText += "s";
                }
            }

            $innerItemHeading.append($("<img src='" + hImg + "'>"));
            $innerItemHeading.append($("<p><span class='ip-range'>" + inObj.ip_lvl2 + "</span>" + hText + "</p>"));

            outsideServerCounter = 0;
            outsideClientCounter = 0;

            // Adding content to the Layer X.
            $itemContent.append($innerItemHeading);
            $itemContent.append($innerItemContent);


        }


        // This part must be done here again.
        let hText = "";
        let hImg = "img/client.png"
        if(outClientCounter > 0) {
            hText += outClientCounter + " Client Asset"

            if(outClientCounter > 1) {
                hText += "s";
            }
        }

        if(outServerCounter > 0) {
            if(outClientCounter > 0) {
                hText += ", ";
                hImg = "img/half.png";
            } else {
                hImg = "img/server.png";
            }

            hText += outServerCounter + " Server Asset"

            if(outServerCounter > 1) {
                hText += "s";
            }
        }


        // Adding content to the Layer X heading.
        $itemHeading.append($("<img src='" + hImg + "'>"));
        $itemHeading.append($("<p><span class='ip-range'>" + obj.ip_lvl1 + "</span>" + hText + "</p>"));

        outClientCounter = 0;
        outServerCounter = 0;

        // Appending main group to the markup.
        $("#accordionWrapper").append($itemHeading);
        $("#accordionWrapper").append($itemContent);


    }



    // This part must be done here again.
    let hText = "";
    let hImg = "img/client.png"
    let mainText = "Client IP Ranges";
    if(countClients > 0) {
        hText += countClients + " Client Asset"

        if(countClients > 1) {
            hText += "s";
        }
    }

    if(countServers > 0) {
        if(countClients > 0) {
            hText += ", ";
            hImg = "img/half.png";
            mainText = "Mixed IP Ranges";
        } else {
            hImg = "img/server.png";
            mainText = "Server IP Ranges";
        }

        hText += countServers + " Server Asset"

        if(countServers > 1) {
            hText += "s";
        }
    }

    $("#main-parent").append($("<img src='" + hImg + "'>"));
    $("#main-parent").append($("<p><span class='ip-range'>" + mainText + "</span>" + hText + "</p>"));





    // Generating random number for markup IDs.
    function randomNumber() {
        return Math.floor(Math.random() * 99999) + 11111;
    }

    // If string too long, cut it and add ...
    function obradi(str) {
        if(str.length > 16) {
            str = str.substring(0,14) + "...";
        }

        return str;
    }
});