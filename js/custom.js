// Customize Jquery Plugins
$(document).ready(function() {
	// Device Slider customize
	$('.flexslider').flexslider({
        animation: "fade",
        touch: true,
        slideshow: true,
		slideshowSpeed: 4000,        
		animationSpeed: 600,
		controlNav: false,
		directionNav: true,
      });
	// Subscription-Form
	$(function() {
			$(".submit-btn").click(function() {
			var x=$("#appendedInputButton").val();
			var atpos=x.indexOf("@");
			var dotpos=x.lastIndexOf(".");
			var email = $("#appendedInputButton").val();
			var dataString = 'email='+ email;
			
			if (atpos<1 || dotpos<atpos+2 || dotpos+2>=x.length)
			{
			$("#appendedInputButton").css({"background-color":"rgba(255, 14, 14, 0.2)"});
			}
			else
			{
			$.ajax({
			type: "POST",
			url: "mail.php",
			data: dataString,
				success: function(){
					$('.subscribe-box').hide();
					$('.newsletter-section h4').text("Thanks for signing up. we will send you latest news about ProApp.");
					$(".newsletter-section h4").css({"text-align":"center", "width":"100%"});
				}
			});
			}
			return false;
			});
	});
});