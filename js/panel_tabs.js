jQuery(document).ready(function ($) {
    $(".panel-tabs-menu li").click(function (e) {
        e.preventDefault();

        $(".panel-tabs-menu li").removeClass('active');
        $(this).addClass('active');
        let tID = $(this).attr('data-panel-tab');

        $(".panel-tabs").removeClass('active');
        $(tID).addClass('active');
    });
});