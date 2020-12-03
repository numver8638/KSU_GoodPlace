"use strict";

const ksu_goodplace = {
    notify: function(type, message, ticks) {
        let notice_template = `<div class="alert alert-${type} alert-dismissible fade show" role="alert">${message}<button class="close" type="button" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button></div>`;
        let noticeBar = $("#notice");

        if (noticeBar == undefined || noticeBar == null) {
            console.warn("cannot find #notice.");
            return;
        }

        var notice = $(notice_template);

        noticeBar.append(notice);

        if (typeof ticks !== "undefined") {
            setTimeout(function() { notice.alert("close"); }, ticks);
        }
    },
    // 16자리 랜덤 문자열을 생성하는 함수.
    generate_id: function() {
        var array = new Uint8Array(16);
        window.crypto.getRandomValues(array);
    
        var str = "";

        for (let b of array) {
            str += b < 16 ? ("0" + b.toString(16)) : b.toString(16);
        }

        return str;
    },
    get_cookie: function(key) {
        let regex = new RegExp(key + "=(.+?)(;|$)");

        let result = document.cookie.match(regex);

        return result !== null ? result[1] : null;
    }
};