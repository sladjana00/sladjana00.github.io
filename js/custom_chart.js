anychart.onDocumentReady(function() {

    // set the data
    let data = [
        {x: "Accessible", value: 85, fill: "#4F73FF"},
        {x: "Inaccessible", value: 15, fill: "#DCDFE8"},
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