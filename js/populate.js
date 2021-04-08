(async () => {

    let res = await fetch(serveraddress + "getPopularPortsByType");
    let json = await res.json();   
    let ports = json.popular_ports;
    let serverports  = json.server_occ;
    let clientports = json.client_occ;

    
    let popular_port_1_name = ports[0];
    let popular_port_2_name = ports[1];
    let popular_port_3_name = ports[2];

    document.getElementById('popular_port_1_name').innerHTML = popular_port_1_name + " TCP";
    document.getElementById('popular_port_2_name').innerHTML = popular_port_2_name + " TCP";
    document.getElementById('popular_port_3_name').innerHTML = popular_port_3_name + " TCP";

    document.getElementById('popular_port_1_clients').style.width = clientports[0] + "%";
    document.getElementById('popular_port_2_clients').style.width = clientports[1] + "%";
    document.getElementById('popular_port_3_clients').style.width = clientports[2] + "%";

    document.getElementById('popular_port_1_servers').style.width = serverports[0] + "%";
    document.getElementById('popular_port_2_servers').style.width = serverports[1] + "%";
    document.getElementById('popular_port_3_servers').style.width = serverports[2] + "%";
})();

(async () => {
    // Get Duration
    let res = await fetch(serveraddress + "getDuration");
    let json = await res.json();   
    let duration = json.content;
    document.getElementById('duration').innerHTML = duration;

    res = await fetch(serveraddress + "getUserName");
    json = await res.json();   
    let username = json.content;
    document.getElementById('username').innerHTML = username;

    res = await fetch(serveraddress + "getDateTime");
    json = await res.json();   
    let datetime = json.content;
    document.getElementById('datetime').innerHTML = datetime;

    res = await fetch(serveraddress + "getFqdn");
    json = await res.json();   
    let fqdn = json.content;
    document.getElementById('fqdn').innerHTML = fqdn;
    document.getElementById('fqdn2').innerHTML = fqdn;

    res = await fetch(serveraddress + "getIP");
    json = await res.json();   
    let ip = json.content;
    document.getElementById('ipaddr').innerHTML = ip;

    res = await fetch(serveraddress + "getAssetsNbr");
    json = await res.json();   
    let nbrAssets = json.content;
    
    document.getElementById('assetsnbr').innerHTML = nbrAssets;

    res = await fetch(serveraddress + "getPercByType");
    json = await res.json();   
    let servers_percentage = json.servers;
    let clients_percentage = json.clients;


    if (servers_percentage == 0 && clients_percentage == 0) {
        res = await fetch(serveraddress + "getAccessiblePercentageLoc");
        json = await res.json();   
        accessible = json.acc;
        total = json.total;
    
        let unknown_percentage = accessible / total * 100;

        document.getElementById('clients_percentage_number').innerHTML = 0;
        document.getElementById('servers_percentage_number').innerHTML = 0;

        document.getElementById('clients_percentage_bar').style.height = "0%";
        document.getElementById('servers_percentage_bar').style.height = "0%";

        document.getElementById('unknown_percentage_number').innerHTML = unknown_percentage.toFixed(1);
        document.getElementById('unknown_percentage_bar').style.height = unknown_percentage.toFixed(1) + "%";
        document.getElementById('clients_label').className = "disabled";
        document.getElementById('servers_label').className = "disabled";
        document.getElementById('unknown_label').className = "enabled";
    } else {
        res = await fetch(serveraddress + "getAccessiblePercentageAD");
        json = await res.json();   
        accessible = json.acc;
        total = json.total;
    
        document.getElementById('clients_percentage_number').innerHTML = clients_percentage.toFixed(1);
        document.getElementById('servers_percentage_number').innerHTML = servers_percentage.toFixed(1);
        document.getElementById('unknown_percentage_number').innerHTML = 0;

        document.getElementById('clients_percentage_bar').style.height = clients_percentage.toFixed(1) + "%";
        document.getElementById('servers_percentage_bar').style.height = servers_percentage.toFixed(1) + "%";
        document.getElementById('unknown_percentage_bar').style.height = "0%";

        document.getElementById('clients_label').className = "enabled";
        document.getElementById('servers_label').className = "enabled";
        document.getElementById('unknown_label').className = "disabled";
    }

})();

(async () => {
    // Get Duration
    let res = await fetch(serveraddress + "getOperatingSystems");
    let json = await res.json();   
    let operatingsystems = json.os;


    document.getElementById('numberOfOS').innerHTML = "Operating Systems (" + operatingsystems.length + ")";

    var OS_content = ''; 

    for (i = 0; i < operatingsystems.length; i++) {
        OS_content += "<p>" + operatingsystems[i] + "</p>";
    }

    document.getElementById('tabs-content-2').innerHTML = OS_content;

})();

(async () => {
    // Get Duration
    let res = await fetch(serveraddress + "getAllOpenPorts");
    let json = await res.json();   
    let open_ports = json.open_ports;

    document.getElementById('numberOfPorts').innerHTML = "Opened Ports (" + open_ports.length + ")";

    var Ports_content = ''; 

    for (i = 0; i < open_ports.length; i++) {
        Ports_content += "<p>" + open_ports[i] + "</p>";
    }

    document.getElementById('tabs-content-3').innerHTML = Ports_content;

})();

$('#NetworkDetails').click(function() { 
    var client = new HttpClient();
    client.get(serveraddress + 'openNetworkDetails', function(response) {
    });

    return false; 
});

$('#AssetsDetails').click(function() {
    var client = new HttpClient();
    client.get(serveraddress + 'openAssetsDetails', function(response) {
    });
     
    return false; 
});


