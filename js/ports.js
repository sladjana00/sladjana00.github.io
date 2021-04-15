jQuery(document).ready(function ($) {

    var client = new HttpClient();

    client.get(serveraddress + 'getADPortsSummary', function (response) {

        var myObj = response.content;
        let portCounter = 0;

        for(let i = 0; i < myObj.length; i++) {
            let obj = myObj[i];

            let scText = countServersClients(obj);
            let $mainDiv = $("<div data-target-modal='#custom-modal2-"+i+"' class='modal-box ops-item'><p class='ops-number'>" + obj.Port + "</p><span class='os-sc-count'>" + scText + "</span></div>");
            $("#openPorts").append($mainDiv);

            $("body").append(generateModal(obj, i, obj.Port));

            portCounter++;
        }

        $("#numberOfPorts").text("Opened Ports (" + portCounter + ")");
    });

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