const ip = 'http://127.0.0.1';
const serveraddress = ip + ':8081/';

const colors = [ "#4F73FF", "#FFC500", "#F26344", "#65D2FD" , "#6A6DE2" , "#00EEAD"];
const emptyColor = "#E7E6DD";
const colorsLabels = ["color-blue", "color-yellow", "color-red", "color-light-blue", "color-purple", "color-green"]; 

const round = (number, decimalPlaces) => {
    const factorOfTen = Math.pow(10, decimalPlaces)
    return Math.round(number * factorOfTen) / factorOfTen
}
  
var HttpClient = function () {
    this.get = function (aUrl, aCallback) {
        var anHttpRequest = new XMLHttpRequest();
        anHttpRequest.responseType = 'json';
        anHttpRequest.onreadystatechange = function () {
            if (anHttpRequest.readyState == 4 && anHttpRequest.status == 200)
                aCallback(anHttpRequest.response);
        }

        anHttpRequest.open("GET", aUrl, true);
        anHttpRequest.send(null);
    }
}

anychart.onDocumentReady(function () {

    var client = new HttpClient();

    client.get(serveraddress + 'getAccessiblePercentageAD', function (response) {

        var accessible = response.acc;
        var total = response.total;

        if (total == 0) {
            client.get(serveraddress + 'getAccessiblePercentageLoc', function (response) {

                var accessible = response.acc;
                var total = response.total;

                acc_per = (accessible / total * 100).toFixed(1);
                not_acc_per = (100 - acc_per).toFixed(1);

                document.getElementById('acc_per').innerHTML = "Accessible " + acc_per + "%";
                document.getElementById('inacc_per').innerHTML = "Inaccessible " + not_acc_per + "%";

                // set the data
                let data = [{
                        x: "Accessible",
                        value: acc_per,
                        fill: "#FF6B5F"
                    },
                    {
                        x: "Inaccessible",
                        value: not_acc_per,
                        fill: "#DCDFE8"
                    },
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

        acc_per = (accessible / total * 100).toFixed(1);
        not_acc_per = (100 - acc_per).toFixed(1);

        document.getElementById('acc_per').innerHTML = "Accessible " + acc_per + "%";
        document.getElementById('inacc_per').innerHTML = "Inaccessible " + not_acc_per + "%";

        // set the data
        let data = [{
                x: "Accessible",
                value: acc_per,
                fill: "#FF6B5F"
            },
            {
                x: "Inaccessible",
                value: not_acc_per,
                fill: "#DCDFE8"
            },
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
anychart.onDocumentReady(function () {

    var client = new HttpClient();

    client.get(serveraddress + 'getADOSPerc', function (response) {

        var object = response;
        var data = [];
        var length = object.length;

        for (index = 0; index < length; index++) {
            var os = object[index].os;
            var perc = round(object[index].perc, 2);
            var color = colors[index]
            data[index] = {
               x: os, 
               value: perc, 
               fill :color
            };
        }

        var zeroElements = 0;
        for (index = 0; index < length; index++) {
            if (data[index].value == 0) {
                zeroElements++;
            }
        }
        
        if ((zeroElements == length) || (index == 0))  {
            data = [{x : "", value : 100, fill : emptyColor}]
        }

        // create a chart and set the data
        let chart = anychart.pie(data);

        // set the container id
        chart.container("osPie");

        // initiate drawing the chart
        chart.draw();


        var labels = "<ul>";
        for (index = 0; index < length; index++) {
            labels += "                            <li class='" + colorsLabels[index] + "'>" + object[index].os + " " + object[index].perc + "% </li>\n";

        }
        labels += "</ul>"

        document.getElementById('os_labels_array').innerHTML = labels;

    });
});

/*
CLIENTS PORTS CHART
 */
anychart.onDocumentReady(function () {

    var client = new HttpClient();

    client.get(serveraddress + 'getADPortsPercClients', function (response) {

        var object = response;
        var data = [];
        var length = object.length;

        for (index = 0; index < length; index++) {
            var port = object[index].port;
            var perc = round(object[index].perc, 2);
            var color = colors[index]
            data[index] = {
               x: port, 
               value: perc, 
               fill :color
            };
        }

        var zeroElements = 0;
        for (index = 0; index < length; index++) {
            if (data[index].value == 0) {
                zeroElements++;
            }
        }
        
        if ((zeroElements == length) || (index == 0))  {
            data = [{x : "", value : 100, fill : emptyColor}]
        }

        // create a chart and set the data
        let chart = anychart.pie(data);

        // set the container id
        chart.container("clientsPorts");

        // initiate drawing the chart
        chart.draw();

        var labels = "";
        for (index = 0; index < length; index++) {
            if (object[index].perc != 0) {
                labels += "                            <li class='" + colorsLabels[index] + "'>" + object[index].port + " " + round(object[index].perc, 2) + "% </li>\n";
            }
        }

        document.getElementById('ports_clients_labels_array').innerHTML = labels;
    });
});

/*
SERVERS PORTS CHART
 */
anychart.onDocumentReady(function () {

    var client = new HttpClient();

    client.get(serveraddress + 'getADPortsPercServers', function (response) {

        var object = response;
        var data = [];
        var length = object.length;

        for (index  = 0; index < length; index++) {
            var port = object[index].port;
            var perc = round(object[index].perc, 2);
            var color = colors[index]
            data[index] = {
               x: port, 
               value: perc, 
               fill :color
            };
        }

        var zeroElements = 0;
        for (index = 0; index < length; index++) {
            if (data[index].value == 0) {
                zeroElements++;
            }
        }
        
        if ((zeroElements == length) || (index == 0))  {
            data = [{x : "", value : 100, fill : emptyColor}]
        }

        // create a chart and set the data
        let chart = anychart.pie(data);

        // set the container id
        chart.container("serversPorts");

        // initiate drawing the chart
        chart.draw();

        var labels = "";
        for (index = 0; index < length; index++) {
            if (object[index].perc != 0) {
                labels += "                            <li class='" + colorsLabels[index] + "'>" + object[index].port + " " + round(object[index].perc, 2) + "% </li>\n";
            }
        }

        document.getElementById('ports_servers_labels_array').innerHTML = labels;
    });
});

/*
UNKNOWN PORTS CHART
 */
anychart.onDocumentReady(function () {

    var client = new HttpClient();

    client.get(serveraddress + 'getADPortsPercUnknown', function (response) {

        var object = response;
        var data = [];
        var length = object.length;

        for (index = 0; index < length; index++) {
            var port = object[index].port;
            var perc = round(object[index].perc, 2);
            var color = colors[index]
            data[index] = {
               x: port, 
               value: perc, 
               fill :color
            };
        }

        var zeroElements = 0;
        for (index = 0; index < length; index++) {
            if (data[index].value == 0) {
                zeroElements++;
            }
        }
        
        if ((zeroElements == length) || (index == 0))  {
            data = [{x : "", value : 100, fill : emptyColor}]
        }

        // create a chart and set the data
        let chart = anychart.pie(data);

        // set the container id
        chart.container("unknownPorts");

        // initiate drawing the chart
        chart.draw();

        var labels = "";
        for (index = 0; index < length; index++) {
            if (object[index].perc != 0) {
                labels += "                            <li class='" + colorsLabels[index] + "'>" + object[index].port + " " + round(object[index].perc, 2) + "% </li>\n";
            }
        }

        document.getElementById('ports_unknown_labels_array').innerHTML = labels;
    });
});