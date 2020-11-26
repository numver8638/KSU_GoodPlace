'use strict';

const ksu_goodplace = {
    notify: function(type, message) {
        let noticeBar = $('#notice');

        if (noticeBar == undefined || noticeBar == null) {
            console.warn("cannot find #notice.");
            return;
        }

        var notice = $("<div>").addClass("alert alert-" + type + " alert-dismissible fade show").attr("role", "alert");

        notice.append(message);

        notice.append(
            $("<button>").addClass("close").attr("type", "button").attr("data-dismiss", "alert").attr("aria-label", "Close").append(
                $("<span>").attr("aria-hidden", "true").append("&times;")
            )
        );

        noticeBar.append(notice);
    },
    // 16자리 랜덤 문자열을 생성하는 함수.
    generate_id: function() {
        var array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
    
        var str = "";

        array.forEach(e => {
            str += e < 16 ? ("0" + e.toString(16)) : e.toString(16); 
        });

        return str;
    },
    get_cookie: function(key) {
        let regex = new RegExp(key + "=(.+?);");

        let result = document.cookie.match(regex);

        return result !== null ? result[1] : null;
    }
};