jQuery(document).ready(function () {
    $(".all-tabs a").click(function (e) {
        e.preventDefault();

        $(".all-tabs a").removeClass('active');
        $(this).addClass('active');
        let cID = $(this).attr('data-target');

        $(".content-item").hide();
        $(cID).slideDown();
    });

    $(".accordion-item-content .accordion-item").click(function (e) {
        e.preventDefault();

        let cID = $(this).attr('data-target');

        $(this).toggleClass('active');

        $("[data-expand='"+ cID +"']").slideToggle();
    });
});