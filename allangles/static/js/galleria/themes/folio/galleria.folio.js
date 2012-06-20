/* Galleria Folio Theme 2012-04-04 | http://galleria.io/license/ | (c) Aino */
(function (a) {
    Galleria.addTheme({
        name: "folio",
        author: "Galleria",
        css: "galleria.folio.css",
        defaults: {
            transition: "pulse",
            thumbCrop: "width",
            imageCrop: !1,
            carousel: !1,
            show: !1,
            easing: "galleriaOut",
            fullscreenDoubleTap: !1,
            trueFullscreen: !1,
            _webkitCursor: !1,
            _animate: !0
        },
        init: function (b) {
            Galleria.requires(1.27, "This version of Folio theme requires Galleria version 1.2.7 or later"), this.addElement("preloader", "loaded", "close", "download").append({
                container: "preloader",
                preloader: "loaded",
                stage: ["star", "download", "close"]
            });
            var c = this,
                d = this.$("stage"),
                e = this.$("thumbnails"),
                f = this.$("images"),
                g = this.$("info"),
                h = this.$("loader"),
                i = this.$("target"),
                j = 0,
                k = i.width(),
                l = 0,
                m = b.show,
                n = window.location.hash.substr(2),
                o = !1,
                p = function (b) {
                    c.$("info").css({
                        left: Math.max(20, a(window).width() / 2 - b / 2 + 10),
                        marginBottom: c.getData().video ? 40 : 0
                    })
                },
                q = function (a) {
                    return Math.min.apply(window, a)
                },
                r = function (a) {
                    return Math.max.apply(window, a)
                },
                s = function (b, c) {
                    c = a.extend({
                        speed: 400,
                        width: 190,
                        onbrick: function () {},
                        onheight: function () {},
                        delay: 0,
                        debug: !1
                    }, c), b = a(b);
                    var d = b.children(),
                        e = b.width(),
                        f = Math.floor(e / c.width),
                        g = [],
                        h, i, j, k, l = {
                            "float": "none",
                            position: "absolute",
                            display: a.browser.safari ? "inline-block" : "block"
                        };
                    if (b.data("colCount") === f) return;
                    b.data("colCount", f);
                    if (!d.length) return;
                    for (h = 0; h < f; h++) g[h] = 0;
                    b.css("position", "relative"), d.css(l).each(function (b, d) {
                        d = a(d);
                        for (h = f - 1; h > -1; h--) g[h] === q(g) && (i = h);
                        j = {
                            top: g[i],
                            left: c.width * i
                        };
                        if (typeof j.top != "number" || typeof j.left != "number") return;
                        c.speed ? window.setTimeout(function (a, b, c) {
                            return function (d) {
                                Galleria.utils.animate(a, c, {
                                    easing: "galleriaOut",
                                    duration: b.speed,
                                    complete: b.onbrick
                                })
                            }
                        }(d, c, j), b * c.delay) : (d.css(j), c.onbrick.call(d)), d.data("height") || d.data("height", d.outerHeight(!0)), g[i] += d.data("height")
                    }), k = r(g);
                    if (k < 0) return;
                    if (typeof k != "number") return;
                    c.speed ? b.animate({
                        height: r(g)
                    }, c.speed, c.onheight) : (b.height(r(g)), c.onheight.call(b))
                };
            Galleria.OPERA && this.$("stage").css("display", "none"), this.bind("fullscreen_enter", function (a) {
                f.css("visibility", "hidden"), d.show(), this.$("container").css("height", "100%"), o = !0
            }), this.bind("fullscreen_exit", function (b) {
                this.getData().iframe && (a(this._controls.getActive().container).find("iframe").remove(), this.$("container").removeClass("iframe")), d.hide(), e.show(), g.hide(), o = !1
            }), this.bind("loadstart", function (a) {
                Galleria.TOUCH && this.$("image-nav").toggle( !! a.galleriaData.iframe)
            }), this.bind("thumbnail", function (d) {
                this.addElement("plus"), Galleria.History && d.index === parseInt(n, 10) && this.enterFullscreen(function () {
                    this.show(n)
                });
                var h = d.thumbTarget,
                    k = this.$("plus").css({
                        display: "block"
                    }).insertAfter(h),
                    o = a(h).parent().data("index", d.index);
                b.showInfo && this.hasInfo(d.index) && k.append("<span>" + this.getData(d.index).title + "</span>"), l = l || a(h).parent().outerWidth(!0), a(h).css("opacity", 0), o.unbind(b.thumbEventType), Galleria.IE ? k.hide() : k.css("opacity", 0), Galleria.TOUCH ? o.bind("touchstart", function () {
                    k.css("opacity", 1)
                }).bind("touchend", function () {
                    k.hide()
                }) : o.hover(function () {
                    Galleria.IE ? k.show() : k.stop().css("opacity", 1)
                }, function () {
                    Galleria.IE ? k.hide() : k.stop().animate({
                        opacity: 0
                    }, 300)
                }), j++, this.$("loaded").css("width", j / this.getDataLength() * 100 + "%"), j === this.getDataLength() && (this.$("preloader").fadeOut(100), s(e, {
                    width: l,
                    speed: b._animate ? 400 : 0,
                    onbrick: function () {
                        var d = this,
                            h = a(d).find("img");
                        window.setTimeout(function (d) {
                            return function () {
                                Galleria.utils.animate(d, {
                                    opacity: 1
                                }, {
                                    duration: b.transition_speed
                                }), d.parent().bind(Galleria.TOUCH ? "mouseup" : "click", function () {
                                    e.hide(), g.hide();
                                    var b = a(this);
                                    c.enterFullscreen(function () {
                                        c.show(b.data("index")), b.data("index") === m && (f.css("visibility", "visible"), g.toggle(c.hasInfo()))
                                    })
                                })
                            }
                        }(h), b._animate ? h.parent().data("index") * 100 : 0)
                    },
                    onheight: function () {
                        i.height(e.height())
                    }
                }))
            }), this.bind("loadstart", function (a) {
                a.cached || h.show()
            }), this.bind("loadfinish", function (c) {
                g.hide(), m = this.getIndex(), f.css("visibility", "visible"), h.hide(), this.hasInfo() && b.showInfo && o && g.fadeIn(b.transition ? b.transitionSpeed : 0), p(a(c.imageTarget).width())
            }), !Galleria.TOUCH && !b._webkitCursor && (this.addIdleState(this.get("image-nav-left"), {
                left: -100
            }), this.addIdleState(this.get("image-nav-right"), {
                right: -100
            }), this.addIdleState(this.get("info"), {
                opacity: 0
            })), this.$("container").css({
                width: b.width,
                height: "auto"
            }), b._webkitCursor && Galleria.WEBKIT && !Galleria.TOUCH && this.$("image-nav-right,image-nav-left").addClass("cur"), Galleria.TOUCH && this.setOptions({
                transition: "fadeslide",
                initialTransition: !1
            }), this.$("close").click(function () {
                c.exitFullscreen()
            }), a(window).resize(function () {
                if (o) {
                    c.getActiveImage() && p(c.getActiveImage().width);
                    return
                }
                var a = i.width();
                a !== k && (k = a, s(e, {
                    width: l,
                    delay: 50,
                    debug: !0,
                    onheight: function () {
                        i.height(e.height())
                    }
                }))
            })
        }
    })
})(jQuery);