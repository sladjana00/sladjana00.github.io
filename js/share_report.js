jQuery(document).ready(function ($) {
    $(".action-button.share-report").click(function (e) {
        e.preventDefault();

        $('body').append("<div class='overlay'></div>");
        $("#shareReportModal").fadeIn();
    });

    $(document).on("click", ".close-report-modal", function (e) {
        e.preventDefault();

        $("#shareReportModal").fadeOut();
        $(".overlay").remove();
    })
});