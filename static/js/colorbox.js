jQuery(document).ready(function ($) {
	$('.colorbox-portfolio a.portfolio-thumb-link').colorbox({
		current: "Image {current} of {total}",
		onOpen: $.fullscreen.unbindKeyboard,
		onClosed: $.fullscreen.bindKeyboard
	});		

	// Portfolio Quicksand filter
	if ($('#portfolio-filter').length) {		
		var $data = $('.portfolio ul').clone();
		
		$('#portfolio-filter li a').click(function () {
			$('#portfolio-filter li').removeClass('active-filter');
			var filter = $(this).data('filter');
			
			if (filter == 'all') {
				var $filteredData = $data.find('li.one-portfolio-item');
			} else {
				var $filteredData = $data.find('li.one-portfolio-item[data-type="'+filter+'"]');
			}
			
			$('.portfolio ul').quicksand($filteredData, {
			    duration: 800,
			    easing: 'easeInOutQuad'
			}, function () {
				$('.colorbox-portfolio a.portfolio-thumb-link').colorbox({
					current: "Image {current} of {total}",
					onOpen: $.fullscreen.unbindKeyboard,
					onClosed: $.fullscreen.bindKeyboard
				});
			});
			
			$(this).parent().addClass('active-filter');
			return false;
		});
	}
});