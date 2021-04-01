jQuery(document).ready(function () {
    $(".all-tabs a").click(function (e) {
        e.preventDefault();

        $(".all-tabs a").removeClass('active');
        $(this).addClass('active');
        let cID = $(this).attr('data-target');

        $(".content-item").hide();
        $(cID).slideDown();
    });

    $(document).on("click", ".accordion-item-content .accordion-item", function (e) {
        e.preventDefault();

        let cID = $(this).attr('data-target');

        $(this).toggleClass('active');

        $("[data-expand='"+ cID +"']").slideToggle();
    });

    let myObj = {
        "data": [
            {
                "IP_LEV1": "10.*.*.*",
                "IP_LEV2": "10.30.*.*",
                "IP_LEV3": "10.30.1.*",
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
                "IP_LEV1": "10.*.*.*",
                "IP_LEV2": "10.30.*.*",
                "IP_LEV3": "10.30.1.*",
                "fqdn": "MIKE-PC.dmpc.com\r\n",
                "hostname": "mike-pc.dmpc.com",
                "type": "Client",
                "ip": "10.30.1.11",
                "computername": "MIKE-PC",
                "operatingsystem": "Windows 10 Enterprise Evaluation",
                "distinguishedname": "CN=MIKE-PC,CN=Computers,DC=dmpc,DC=com",
                "tcpports": ""
            },
            {
                "IP_LEV1": "fe80:*:*:*",
                "IP_LEV2": "fe80::*:*",
                "IP_LEV3": "fe80::e5dc:*",
                "fqdn": "pam-pc.dmpc.com\r\n",
                "hostname": "pam-pc.dmpc.com",
                "type": "Client",
                "ip": "fe80::e5dc:312f:5295:74db",
                "computername": "PAM-PC",
                "operatingsystem": "Windows 10 Enterprise Evaluation",
                "distinguishedname": "CN=PAM-PC,CN=Computers,DC=dmpc,DC=com",
                "tcpports": "8081 135 445 3389 139"
            }
        ]
    }

    myObj = myObj.data;
    let itemContentHTML = "";

    for(let i = 0; i < myObj.length; i++) {

        let acc = i+1;

        if(i == 0) {
            itemContentHTML = $('div[data-expand="accordion-expand-content1-1"]')[0].outerHTML;
        } else {
            let itemTitle = ' <div class="accordion-item" data-target="accordion-expand-content'+acc+'-1">' +
                '                            <img src="img/half.png">' +
                '                            <p><span class="ip-range">Mixed IP Rangers</span>Client Asset, 1 Server Asset</p>' +
                '                        </div>'

            itemContentHTML = $('div[data-expand="accordion-expand-content1-1"]')[0].outerHTML;


            itemContentHTML = replaceAll(itemContentHTML, "accordion-expand-content1-1", "accordion-expand-content"+acc+"-1");
            itemContentHTML = replaceAll(itemContentHTML, "accordion-expand-content1-2", "accordion-expand-content"+acc+"-2");
            itemContentHTML = replaceAll(itemContentHTML, "accordion-expand-content1-3", "accordion-expand-content"+acc+"-3");
            itemContentHTML = replaceAll(itemContentHTML, "accordion-expand-content1-4", "accordion-expand-content"+acc+"-4");
            itemContentHTML = replaceAll(itemContentHTML, "accordion-expand-content1-5", "accordion-expand-content"+acc+"-5");


            $("#accordionWrapper").append(itemTitle + itemContentHTML);
        }


        // ITEM IPs
        $('div[data-target="accordion-expand-content'+acc+'-2"] .ip-range').text(myObj[i].IP_LEV1);
        $('div[data-target="accordion-expand-content'+acc+'-3"] .ip-range').text(myObj[i].IP_LEV2);
        $('div[data-target="accordion-expand-content'+acc+'-4"] .ip-range').text(myObj[i].IP_LEV3);

        // ITEM data
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-ip').text(myObj[i].ip);
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-date-time').text("01/31/2021 21:42");
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-type').text(myObj[i].type);
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-name').text(myObj[i].computername);
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-os').text(myObj[i].operatingsystem);
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-management').text("Managed");
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-tcp-ports').text(myObj[i].tcpports);
        $('div[data-expand="accordion-expand-content'+acc+'-4"] .accordion-item-resource .resource-udp-ports').text("udp ports");

    }


    function replaceAll(string, search, replace) {
        return string.split(search).join(replace);
    }
});