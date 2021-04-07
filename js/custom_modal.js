jQuery(document).ready(function ($) {
    $(document).on("click", ".modal-box", function (e) {
        e.preventDefault();

        $('body').append("<div class='overlay'></div>");

        let id = $(this).attr('data-target-modal');
        $(id).fadeIn();
    });

    $(document).on("click", ".modal-item-heading", function (e) {
        e.preventDefault();

        let id = $(this).attr('data-modal-item-target');

        $(this).toggleClass('active');
        $(id).slideToggle();
    });

    $(document).on("click", ".close-modal", function (e) {
        e.preventDefault();
        $(".custom-modal").fadeOut();
        $(".overlay").remove();
    })
});