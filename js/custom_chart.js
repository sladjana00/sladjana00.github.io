const ip = 'http://127.0.0.1';
const serveraddress = ip + ':8081/';

var HttpClient = function() {
    this.get = function(aUrl, aCallback) {
        var anHttpRequest = new XMLHttpRequest();
        anHttpRequest.responseType = 'json';
        anHttpRequest.onreadystatechange = function() { 
            if (anHttpRequest.readyState == 4 && anHttpRequest.status == 200)
                aCallback(anHttpRequest.response);
        }

        anHttpRequest.open( "GET", aUrl, true );            
        anHttpRequest.send( null );
    }
}

anychart.onDocumentReady(function() {

    var client = new HttpClient();

    client.get(serveraddress + 'getAccessiblePercentageAD', function(response) {

        var  accessible = response.acc;
        var total = response.total;
        
        if (total == 0) {
            client.get(serveraddress + 'getAccessiblePercentageLoc', function(response) {

                var  accessible = response.acc;
                var total = response.total;
                
                acc_per = (accessible /total * 100).toFixed(1);
                not_acc_per = (100 -  acc_per).toFixed(1);
        
                document.getElementById('acc_per').innerHTML = "Accessible " + acc_per + "%";
                document.getElementById('inacc_per').innerHTML = "Inaccessible " + not_acc_per + "%";
        
                // set the data
                let data = [
                    {x: "Accessible", value: acc_per, fill: "#FF6B5F"},
                    {x: "Inaccessible", value: not_acc_per, fill: "#DCDFE8"},
                ];
        
                // create the chart
                let chart = anychart.pie();
        
                chart.legend().enabled(false);
        
                // add the data
                chart.data(data);
        
                // display the chart in the container
                chart.container('pieChart');
                chart.draw();
            });
            return false;

        }

        acc_per = (accessible /total * 100).toFixed(1);
        not_acc_per = (100 -  acc_per).toFixed(1);

        document.getElementById('acc_per').innerHTML = "Accessible " + acc_per + "%";
        document.getElementById('inacc_per').innerHTML = "Inaccessible " + not_acc_per + "%";

        // set the data
        let data = [
            {x: "Accessible", value: acc_per, fill: "#FF6B5F"},
            {x: "Inaccessible", value: not_acc_per, fill: "#DCDFE8"},
        ];

        // create the chart
        let chart = anychart.pie();

        chart.legend().enabled(false);

        // add the data
        chart.data(data);

        // display the chart in the container
        chart.container('pieChart');
        chart.draw();
    });
});

/*
OS CHART
 */
anychart.onDocumentReady(function() {

    // create data
    let data = [
        {x: "Windows", value: 45, fill: "#4F73FF"},
        {x: "Ubuntu", value: 20, fill: "#FFC500"},
        {x: "Windows Server", value: 15, fill: "#F26344"},
        {x: "Red Hat", value: 12, fill: "#6A6DE2"},
        {x: "Other", value: 8, fill: "#65D2FD"}
    ];

    // create a chart and set the data
    let chart = anychart.pie(data);

    // set the container id
    chart.container("osPie");

    // initiate drawing the chart
    chart.draw();

});

/*
CLIENTS PORTS CHART
 */
anychart.onDocumentReady(function() {

    // create data
    let data = [
        {x: "135", value: 48, fill: "#4F73FF"},
        {x: "139", value: 16, fill: "#FFC500"},
        {x: "21", value: 16, fill: "#F26344"},
        {x: "80", value: 8, fill: "#65D2FD"},
        {x: "110", value: 10, fill: "#6A6DE2"},
        {x: "Other", value: 2, fill: "#00EEAD"}
    ];

    // create a chart and set the data
    let chart = anychart.pie(data);

    // set the container id
    chart.container("clientsPorts");

    // initiate drawing the chart
    chart.draw();

});

/*
SERVERS PORTS CHART
 */
anychart.onDocumentReady(function() {

    // create data
    let data = [
        {x: "135", value: 48, fill: "#4F73FF"},
        {x: "139", value: 16, fill: "#FFC500"},
        {x: "21", value: 16, fill: "#F26344"},
        {x: "80", value: 8, fill: "#65D2FD"},
        {x: "110", value: 10, fill: "#6A6DE2"},
        {x: "Other", value: 2, fill: "#00EEAD"}
    ];

    // create a chart and set the data
    let chart = anychart.pie(data);

    // set the container id
    chart.container("serversPorts");

    // initiate drawing the chart
    chart.draw();

});

/*
UNKNOWN PORTS CHART
 */
anychart.onDocumentReady(function() {

    // create data
    let data = [
        {x: "135", value: 48, fill: "#4F73FF"},
        {x: "139", value: 16, fill: "#FFC500"},
        {x: "21", value: 16, fill: "#F26344"},
        {x: "80", value: 8, fill: "#65D2FD"},
        {x: "110", value: 10, fill: "#6A6DE2"},
        {x: "Other", value: 2, fill: "#00EEAD"}
    ];

    // create a chart and set the data
    let chart = anychart.pie(data);

    // set the container id
    chart.container("unknownPorts");

    // initiate drawing the chart
    chart.draw();

});