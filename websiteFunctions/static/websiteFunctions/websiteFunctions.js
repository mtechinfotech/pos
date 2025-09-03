/**
 * Created by usman on 7/26/17.
 */

// Global function for deleting staging sites
function deleteStagingGlobal(stagingId) {
    if (confirm("Are you sure you want to delete this staging site? This action cannot be undone.")) {
        // Redirect to WordPress list with delete parameter
        window.location.href = "/websites/ListWPSites?DeleteID=" + stagingId;
    }
}
function getCookie(name) {
    var cookieValue = null;
    var t = document.cookie;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}


var arry = []

function selectpluginJs(val) {
    $('#mysearch').hide()
    arry.push(val)

    // console.log(arry)
    document.getElementById('selJS').innerHTML = "";

    for (var i = 0; i < arry.length; i++) {
        $('#selJS').show()
        var mlm = '<span style="background-color: #12207a; color: #FFFFFF; padding: 5px;  border-radius: 30px"> ' + arry[i] + ' </span>&nbsp &nbsp'
        $('#selJS').append(mlm)
    }


}


var DeletePluginURL;

function DeletePluginBuucket(url) {
    DeletePluginURL = url;
}

function FinalDeletePluginBuucket() {
    window.location.href = DeletePluginURL;
}

var SPVal;

app.controller('WPAddNewPlugin', function ($scope, $http, $timeout, $window, $compile) {
    $scope.webSiteCreationLoading = true;

    $scope.SearchPluginName = function (val) {
        $scope.webSiteCreationLoading = false;
        SPVal = val;
        url = "/websites/SearchOnkeyupPlugin";

        var searchcontent = $scope.searchcontent;


        var data = {
            pluginname: searchcontent
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;

            if (response.data.status === 1) {
                if (SPVal == 'add') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option onclick="selectpluginJs(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        $('#mysearch').append(tml);
                    }
                } else if (SPVal == 'eidt') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option  ng-click="Addplugin(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        var temp = $compile(tml)($scope)
                        angular.element(document.getElementById('mysearch')).append(temp);
                    }

                }


            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.AddNewplugin = function () {

        url = "/websites/AddNewpluginAjax";

        var bucketname = $scope.PluginbucketName

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        var data = {
            config: arry,
            Name: bucketname
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Bucket created.',
                    type: 'success'
                });
                location.reload();
            } else {

                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.deletesPlgin = function (val) {

        url = "/websites/deletesPlgin";


        var data = {
            pluginname: val,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    }

    $scope.Addplugin = function (slug) {
        $('#mysearch').hide()

        url = "/websites/Addplugineidt";


        var data = {
            pluginname: slug,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }


    }

});

var domain_check = 0;

function checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        domain_check = 0;
        document.getElementById('Test_Domain').style.display = "block";
        document.getElementById('Own_Domain').style.display = "none";

    } else {
        document.getElementById('Test_Domain').style.display = "none";
        document.getElementById('Own_Domain').style.display = "block";
        domain_check = 1;
    }

    // alert(domain_check);
}

app.controller('createWordpress', function ($scope, $http, $timeout, $compile, $window) {
    $scope.webSiteCreationLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    // Password generation function
    $scope.randomPassword = function(length) {
        var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        var password = "";
        for (var i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    };

    // Initialize showPassword
    $scope.showPassword = false;

    var statusFile;

    $scope.createWordPresssite = function () {

        $scope.webSiteCreationLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;


        $scope.currentStatus = "Starting creation..";

        var apacheBackend = 0;

        if ($scope.apacheBackend === true) {
            apacheBackend = 1;
        } else {
            apacheBackend = 0
        }

        var package = $scope.packageForWebsite;
        var websiteOwner = $scope.websiteOwner;
        var WPtitle = $scope.WPtitle;

        // if (domain_check == 0) {
        //     var Part2_domainNameCreate = document.getElementById('Part2_domainNameCreate').value;
        //     var domainNameCreate = document.getElementById('TestDomainNameCreate').value + Part2_domainNameCreate;
        // }
        // if (domain_check == 1) {
        //
        //     var domainNameCreate = $scope.own_domainNameCreate;
        // }

        var domainNameCreate = $scope.domainNameCreate;


        var WPUsername = $scope.WPUsername;
        var adminEmail = $scope.adminEmail;
        var WPPassword = $scope.WPPassword;
        var WPVersions = $scope.WPVersions;
        var pluginbucket = $scope.pluginbucket;
        var autoupdates = $scope.autoupdates;
        var pluginupdates = $scope.pluginupdates;
        var themeupdates = $scope.themeupdates;

        if (domain_check == 0) {

            var path = "";

        }
        if (domain_check = 1) {

            var path = $scope.installPath;

        }


        var home = "1";

        if (typeof path != 'undefined') {
            home = "0";
        }

        //alert(domainNameCreate);
        var data = {

            title: WPtitle,
            domain: domainNameCreate,
            WPVersion: WPVersions,
            pluginbucket: pluginbucket,
            adminUser: WPUsername,
            Email: adminEmail,
            PasswordByPass: WPPassword,
            AutomaticUpdates: autoupdates,
            Plugins: pluginupdates,
            Themes: themeupdates,
            websiteOwner: websiteOwner,
            package: package,
            home: home,
            path: path,
            apacheBackend: apacheBackend
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        var url = "/websites/submitWorpressCreation";

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $scope.goBackDisable = false;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    };
    $scope.goBack = function () {
        $scope.webSiteCreationLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $scope.webSiteCreationLoading = false;
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }


});


//........... delete wp list
var FurlDeleteWP;

function DeleteWPNow(url) {
    FurlDeleteWP = url;
}

function FinalDeleteWPNow() {
    window.location.href = FurlDeleteWP;
}

var DeploytoProductionID;

function DeployToProductionInitial(vall) {
    DeploytoProductionID = vall;
}

// Simplified staging domain input - checkbox functionality removed

app.controller('WPsiteHome', function ($scope, $http, $timeout, $compile, $window) {
    var CheckBoxpasssword = 0;
    
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;
    $scope.searchIndex = 0;

    $(document).ready(function () {
        var checkstatus = document.getElementById("wordpresshome");
        if (checkstatus !== null) {
            $scope.LoadWPdata();
        }
    });

    $scope.LoadWPdata = function () {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/FetchWPdata";

        var data = {
            WPid: $('#WPid').html(),
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#WPVersion').text(response.data.ret_data.version);
                if (response.data.ret_data.lscache === 1) {
                    $('#lscache').prop('checked', true);
                }
                if (response.data.ret_data.debugging === 1) {
                    $('#debugging').prop('checked', true);
                }
                
                // Set search index state
                $scope.searchIndex = response.data.ret_data.searchIndex;
                
                if (response.data.ret_data.maintenanceMode === 1) {
                    $('#maintenanceMode').prop('checked', true);
                }
                if (response.data.ret_data.wpcron === 1) {
                    $('#wpcron').prop('checked', true);
                }
                if (response.data.ret_data.passwordprotection == 1) {
                    var dc = '<input type="checkbox" checked ng-click="UpdateWPSettings(\'PasswordProtection\')" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    var mp = $compile(dc)($scope);
                    angular.element(document.getElementById('prsswdprodata')).append(mp);
                    CheckBoxpasssword = 1;
                } else {
                    var dc = '<input type="checkbox" data-toggle="modal" data-target="#Passwordprotection" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    $('#prsswdprodata').append(dc);
                    CheckBoxpasssword = 0;
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            console.error('Failed to load WP data:', error);
        });
    };

    $scope.UpdateWPSettings = function (setting) {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/UpdateWPSettings";
        var data;

        if (setting === "PasswordProtection") {
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                PPUsername: CheckBoxpasssword == 0 ? $scope.PPUsername : '',
                PPPassword: CheckBoxpasssword == 0 ? $scope.PPPassword : ''
            };
        } else {
            var settingValue;
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                settingValue = $scope.searchIndex;
            } else {
                settingValue = $('#' + setting).is(":checked") ? 1 : 0;
            }
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                settingValue: settingValue
            };
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!',
                    type: 'success'
                });
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                // Revert the change on error
                if (setting === 'searchIndex') {
                    $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                }
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            // Revert the change on error
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
            }
            console.error('Failed to update setting:', error);
        });
    };

    $scope.GetCurrentPlugins = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentPlugins";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#PluginBody').html('');
                var plugins = JSON.parse(response.data.plugins);
                plugins.forEach(AddPlugins);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.GetCurrentThemes = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentThemes";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {

                $('#ThemeBody').html('');
                var themes = JSON.parse(response.data.themes);
                themes.forEach(AddThemes);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.UpdatePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdatePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Plugins in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeletePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeletePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Plugin in Background!',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    $scope.ChangeStatus = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/ChangeStatus";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Changed Plugin state Successfully !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    function AddPlugins(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddPluginToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdatePlugins(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger btn-sm"><i class="fas fa-sync-alt"></i> Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeletePlugins(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-sm" type="button"><i class="fas fa-trash"></i> Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#PluginBody', temp)
    }

    $scope.UpdateThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdateThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Theme in background !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeleteThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeleteThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Theme in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    $scope.ChangeStatusThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            theme: theme,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/StatusThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Change Theme state in Bsckground!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    function AddThemes(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddThemeToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdateThemes(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger btn-sm"><i class="fas fa-sync-alt"></i> Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeleteThemes(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-sm" type="button"><i class="fas fa-trash"></i> Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#ThemeBody', temp)
    }

    var statusFile; // Declare statusFile at controller scope
    
    $scope.CreateStagingNow = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation Staging..";

        // Get staging name
        var stagingName = $('#stagingName').val();
        if (!stagingName) {
            new PNotify({
                title: 'Error!',
                text: 'Please enter a staging name',
                type: 'error'
            });
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            return;
        }

        // Get staging domain from the simplified input
        var domainNameCreate = $('#stagingDomainName').val() || $scope.stagingDomainName;
        if (!domainNameCreate) {
            new PNotify({
                title: 'Error!',
                text: 'Please enter a staging domain',
                type: 'error'
            });
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            return;
        }
        
        var data = {
            StagingName: stagingName,
            StagingDomain: domainNameCreate,
            WPid: $('#WPid').html(),
        }
        var url = "/websites/CreateStagingNow";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            //$('#wordpresshomeloading').hide();

            if (response.data.abort === 1) {
                if (response.data.installStatus === 1) {

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;


                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();


                } else {

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            //$('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    $scope.fetchstaging = function () {

        // Ensure DOM is ready
        $timeout(function() {
            // Check if the staging table exists
            if ($('#StagingBody').length === 0) {
                console.error('StagingBody table not found in DOM');
                return;
            }

            $('#wordpresshomeloading').show();
            $scope.wordpresshomeloading = false;

            var url = "/websites/fetchstaging";

            var data = {
                WPid: $('#WPid').html(),
            }

            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };


            $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


            function ListInitialDatas(response) {
                wordpresshomeloading = true;
                $('#wordpresshomeloading').hide();

                if (response.data.status === 1) {

                    //   $('#ThemeBody').html('');
                    // var themes = JSON.parse(response.data.themes);
                    // themes.forEach(AddThemes);

                    $('#StagingBody').html('');
                    console.log('Staging response:', response.data);
                    
                    try {
                        var staging = JSON.parse(response.data.wpsites);
                        console.log('Parsed staging data:', staging);
                        
                        if (staging && staging.length > 0) {
                            staging.forEach(function(site, index) {
                                console.log('Processing staging site ' + index + ':', site);
                                AddStagings(site, index, staging);
                            });
                        } else {
                            $('#StagingBody').html('<tr><td colspan="4" class="text-center">No staging sites found</td></tr>');
                        }
                    } catch (e) {
                        console.error('Error parsing staging data:', e);
                        $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error loading staging sites</td></tr>');
                    }

                } else {
                    console.error("Error from server:", response.data.error_message);
                    $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error: ' + response.data.error_message + '</td></tr>');
                }

            }

            function cantLoadInitialDatas(response) {
                $('#wordpresshomeloading').hide();
                console.error("Request failed:", response);
                $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Failed to load staging sites</td></tr>');
            }
        }, 100); // Small delay to ensure DOM is ready

    };

    $scope.fetchDatabase = function () {

        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;

        var url = "/websites/fetchDatabase";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#DB_Name').html(response.data.DataBaseName);
                $('#DB_User').html(response.data.DataBaseUser);
                $('#tableprefix').html(response.data.tableprefix);
            } else {
                alert("Error data.error_message:" + response.data.error_message)

            }
        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            alert("Error" + response)

        }

    };

    $scope.SaveUpdateConfig = function () {
        $('#wordpresshomeloading').show();
        var data = {
            AutomaticUpdates: $('#AutomaticUpdates').find(":selected").text(),
            Plugins: $('#Plugins').find(":selected").text(),
            Themes: $('#Themes').find(":selected").text(),
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/SaveUpdateConfig";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Update Configurations Sucessfully!.',
                    type: 'success'
                });
                $("#autoUpdateConfig").modal('hide');
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }
    };

    function AddStagings(value, index, array) {
        console.log('Adding staging site:', value);
        
        // Ensure all required properties exist
        if (!value || !value.id) {
            console.error('Invalid staging site data:', value);
            return;
        }
        
        // Check if table exists
        if ($('#StagingBody').length === 0) {
            console.error('StagingBody table not found');
            return;
        }
        
        var FinalMarkup = '<tr>';
        
        // Add columns in correct order: Name, Domain, Path, Actions
        FinalMarkup += '<td><a href="/websites/WPHome?ID=' + (value.id || '') + '">' + (value.name || 'Unnamed') + '</a></td>';
        FinalMarkup += '<td>' + (value.Domain || '') + '</td>';
        FinalMarkup += '<td>' + (value.path || '') + '</td>';
        FinalMarkup += '<td>' +
            '<button onclick="DeployToProductionInitial(' + value.id + ')" data-toggle="modal" data-target="#DeployToProduction" style="margin-right: 10px;" aria-label="" type="button" class="btn btn-outline-primary btn-sm">' +
            '<i class="fas fa-rocket"></i> Deploy to Production</button>' +
            '<button onclick="deleteStagingGlobal(' + value.id + ')" aria-label="" class="btn btn-danger btn-sm" type="button"><i class="fas fa-trash"></i> Delete</button>' +
            '</td>';
        
        FinalMarkup += '</tr>';
        
        console.log('Appending markup to table:', FinalMarkup);
        AppendToTable('#StagingBody', FinalMarkup);
        console.log('Table content after append:', $('#StagingBody').html());
    }

    $scope.FinalDeployToProduction = function () {

        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        var data = {
            WPid: $('#WPid').html(),
            StagingID: DeploytoProductionID
        }

        var url = "/websites/DeploytoProduction";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deploy To Production start!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }

    };


    $scope.CreateBackup = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting creation Backups..";
        var data = {
            WPid: $('#WPid').html(),
            Backuptype: $('#backuptype').val()
        }
        var url = "/websites/WPCreateBackup";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Creating Backups!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            alert(response)

        }

    };
    
    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            if (response.data.abort === 1) {
                $('#wordpresshomeloading').hide();

                if (response.data.installStatus === 1) {
                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    
                    // Re-enable buttons
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // For backup operations, refresh the backup list
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Backup created successfully!</span>');
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#backupStatus').text('');
                        }, 5000);
                    }
                    // For staging operations, refresh the staging list
                    else {
                        $('#stagingStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Staging site created successfully!</span>');
                        $scope.fetchstaging();
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#stagingStatus').text('');
                        }, 5000);
                    }

                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }

                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }

    }

    $scope.installwpcore = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/installwpcore";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched..',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    $scope.dataintegrity = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/dataintegrity";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    $scope.updateSetting = function(site, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: site.id,
            setting: setting,
            value: site[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && site[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    site.PPUsername = "";
                    site.PPPassword = "";
                    $scope.currentWP = site;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.submitPasswordProtection = function() {
        console.log('submitPasswordProtection called');
        console.log('Current WP:', $scope.currentWP);
        
        if (!$scope.currentWP) {
            console.error('No WordPress site selected');
            new PNotify({
                title: 'Error!',
                text: 'No WordPress site selected.',
                type: 'error'
            });
            return;
        }

        if (!$scope.currentWP.PPUsername || !$scope.currentWP.PPPassword) {
            console.error('Missing username or password');
            new PNotify({
                title: 'Error!',
                text: 'Please provide both username and password',
                type: 'error'
            });
            return;
        }

        var data = {
            siteId: $scope.currentWP.id,
            setting: 'password-protection',
            value: 1,
            username: $scope.currentWP.PPUsername,
            password: $scope.currentWP.PPPassword
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log('Sending request with data:', data);
        $('#passwordProtectionModal').modal('hide');

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            console.log('Received response:', response);
            if (response.data.status) {
                new PNotify({
                    title: 'Success!',
                    text: 'Password protection enabled successfully!',
                    type: 'success'
                });
            } else {
                $scope.currentWP.passwordProtection = false;
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message || 'Failed to enable password protection',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            console.error('Request failed:', error);
            $scope.currentWP.passwordProtection = false;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server',
                type: 'error'
            });
        });
    };

});


var PluginsList = [];


function AddPluginToArray(cBox, name) {
    if (cBox.checked) {
        PluginsList.push(name);
        // alert(PluginsList);
    } else {
        const index = PluginsList.indexOf(name);
        if (index > -1) {
            PluginsList.splice(index, 1);
        }
        // alert(PluginsList);
    }
}

var ThemesList = [];

function AddThemeToArray(cBox, name) {
    if (cBox.checked) {
        ThemesList.push(name);
        // alert(ThemesList);
    } else {
        const index = ThemesList.indexOf(name);
        if (index > -1) {
            ThemesList.splice(index, 1);
        }
        // alert(ThemesList);
    }
}


function AppendToTable(table, markup) {
    try {
        if ($(table).length === 0) {
            console.error('Table element not found:', table);
            return false;
        }
        
        console.log('Appending to table:', table);
        console.log('Markup:', markup);
        
        $(table).append(markup);
        
        console.log('Successfully appended. Table now has', $(table).find('tr').length, 'rows');
        return true;
    } catch (e) {
        console.error('Error appending to table:', e);
        return false;
    }
}


//..................Restore Backup Home


app.controller('RestoreWPBackup', function ($scope, $http, $timeout, $window) {
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;


    $scope.checkmethode = function () {
        var val = $('#RestoreMethode').children("option:selected").val();
        if (val == 1) {
            $('#Newsitediv').show();
            $('#exinstingsitediv').hide();
        } else if (val == 0) {
            $('#exinstingsitediv').show();
            $('#Newsitediv').hide();
        } else {

        }
    };


    $scope.RestoreWPbackupNow = function () {
        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Start Restoring WordPress..";

        var Domain = $('#wprestoresubdirdomain').val()
        var path = $('#wprestoresubdirpath').val();
        var home = "1";

        if (typeof path != 'undefined' || path != '') {
            home = "0";
        }
        if (typeof path == 'undefined') {
            path = "";
        }


        var backuptype = $('#backuptype').html();
        var data;
        if (backuptype == "DataBase Backup") {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: '',
                path: path,
                home: home,
            }
        } else {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: Domain,
                path: path,
                home: home,
            }

        }

        var url = "/websites/RestoreWPbackupNow";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        // console.log(data)

        var d = $('#DesSite').children("option:selected").val();
        var c = $("input[name=Newdomain]").val();
        // if (d == -1 || c == "") {
        //     alert("Please Select Method of Backup Restore");
        // } else {
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        // }


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Restoring process starts!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $('#wordpresshomeloading').hide();
                $scope.wordpresshomeloading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    }

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            if (response.data.abort === 1) {
                $('#wordpresshomeloading').hide();

                if (response.data.installStatus === 1) {
                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    
                    // Re-enable buttons
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // For backup operations, refresh the backup list
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Backup created successfully!</span>');
                        if (typeof window.fetchBackupList === 'function') {
                            window.fetchBackupList();
                        }
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#backupStatus').text('');
                        }, 5000);
                    }
                    // For staging operations, refresh the staging list
                    else {
                        $('#stagingStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Staging site created successfully!</span>');
                        $scope.fetchstaging();
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#stagingStatus').text('');
                        }, 5000);
                    }


                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };
});


//.......................................Remote Backup

//........... delete DeleteBackupConfigNow

function DeleteBackupConfigNow(url) {
    window.location.href = url;
}

function DeleteRemoteBackupsiteNow(url) {
    window.location.href = url;
}

function DeleteBackupfileConfigNow(url) {
    window.location.href = url;
}


app.controller('RemoteBackupConfig', function ($scope, $http, $timeout, $window) {
    $scope.RemoteBackupLoading = true;
    $scope.SFTPBackUpdiv = true;

    $scope.EndpointURLdiv = true;
    $scope.Selectprovider = true;
    $scope.S3keyNamediv = true;
    $scope.Accesskeydiv = true;
    $scope.SecretKeydiv = true;
    $scope.SelectRemoteBackuptype = function () {
        var val = $scope.RemoteBackuptype;
        if (val == "SFTP") {
            $scope.SFTPBackUpdiv = false;
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        } else if (val == "S3") {
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = false;
            $scope.S3keyNamediv = false;
            $scope.Accesskeydiv = false;
            $scope.SecretKeydiv = false;
            $scope.SFTPBackUpdiv = true;
        } else {
            $scope.RemoteBackupLoading = true;
            $scope.SFTPBackUpdiv = true;

            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        }
    }

    $scope.SelectProvidertype = function () {
        $scope.EndpointURLdiv = true;
        var provider = $scope.Providervalue
        if (provider == 'Backblaze') {
            $scope.EndpointURLdiv = false;
        } else {
            $scope.EndpointURLdiv = true;
        }
    }

    $scope.SaveBackupConfig = function () {
        $scope.RemoteBackupLoading = false;
        var Hname = $scope.Hostname;
        var Uname = $scope.Username;
        var Passwd = $scope.Password;
        var path = $scope.path;
        var type = $scope.RemoteBackuptype;
        var Providervalue = $scope.Providervalue;
        var data;
        if (type == "SFTP") {

            data = {
                Hname: Hname,
                Uname: Uname,
                Passwd: Passwd,
                path: path,
                type: type
            }
        } else if (type == "S3") {
            if (Providervalue == "Backblaze") {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    EndUrl: $scope.EndpointURL,
                    type: type
                }
            } else {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    type: type
                }

            }

        }
        var url = "/websites/SaveBackupConfig";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    }

});

var UpdatescheduleID;
app.controller('BackupSchedule', function ($scope, $http, $timeout, $window) {
    $scope.BackupScheduleLoading = true;
    $scope.SaveBackupSchedule = function () {
        $scope.RemoteBackupLoading = false;
        var FileRetention = $scope.Fretention;
        var Backfrequency = $scope.Bfrequency;


        var data = {
            FileRetention: FileRetention,
            Backfrequency: Backfrequency,
            ScheduleName: $scope.ScheduleName,
            RemoteConfigID: $('#RemoteConfigID').html(),
            BackupType: $scope.BackupType
        }
        var url = "/websites/SaveBackupSchedule";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };


    $scope.getupdateid = function (ID) {
        UpdatescheduleID = ID;
    }

    $scope.UpdateRemoteschedules = function () {
        $scope.RemoteBackupLoading = false;
        var Frequency = $scope.RemoteFrequency;
        var fretention = $scope.RemoteFileretention;

        var data = {
            ScheduleID: UpdatescheduleID,
            Frequency: Frequency,
            FileRetention: fretention
        }
        var url = "/websites/UpdateRemoteschedules";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    };

    $scope.AddWPsiteforRemoteBackup = function () {
        $scope.RemoteBackupLoading = false;


        var data = {
            WpsiteID: $('#Wpsite').val(),
            RemoteScheduleID: $('#RemoteScheduleID').html()
        }
        var url = "/websites/AddWPsiteforRemoteBackup";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };
});
/* Java script code to create account */

var website_create_domain_check = 0;

function website_create_checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        website_create_domain_check = 0;
        document.getElementById('Website_Create_Test_Domain').style.display = "block";
        document.getElementById('Website_Create_Own_Domain').style.display = "none";

    } else {
        document.getElementById('Website_Create_Test_Domain').style.display = "none";
        document.getElementById('Website_Create_Own_Domain').style.display = "block";
        website_create_domain_check = 1;
    }

    // alert(domain_check);
}


/* Java script code to create account ends here */

/* Java script code to list accounts */

$("#listFail").hide();


app.controller('listWebsites', function ($scope, $http, $window) {
    $scope.web = {};
    $scope.WebSitesList = [];
    $scope.loading = true; // Add loading state
    $scope.expandedSites = {}; // Track which sites are expanded

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    // Function to toggle site expansion
    $scope.toggleSite = function(site) {
        if (!$scope.expandedSites[site.domain]) {
            $scope.expandedSites[site.domain] = true;
            site.loading = true;
            // You can add any data fetching logic here if needed
            setTimeout(function() {
                site.loading = false;
                $scope.$apply();
            }, 500);
        } else {
            $scope.expandedSites[site.domain] = false;
        }
    };

    // Function to check if site is expanded
    $scope.isExpanded = function(siteId) {
        return $scope.expandedSites[siteId];
    };

    // Function to check if site data is loaded
    $scope.isDataLoaded = function(site) {
        return site.version !== undefined;
    };

    // Initial fetch of websites
    $scope.getFurtherWebsitesFromDB = function () {
        $scope.loading = true; // Set loading to true when starting fetch
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };

        var dataurl = "/websites/fetchWebsitesList";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $("#listFail").hide();
                // Expand the first site by default
                if ($scope.WebSitesList.length > 0) {
                    $scope.expandedSites[$scope.WebSitesList[0].domain] = true;
                }
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            $("#listFail").fadeIn();
            $scope.errorMessage = error.message || 'An error occurred while fetching websites';
            $scope.loading = false; // Set loading to false on error
        });
    };

    // Call it immediately
    $scope.getFurtherWebsitesFromDB();

    $scope.showWPSites = function(domain) {
        console.log('showWPSites called for domain:', domain);
        
        // Make sure domain is defined
        if (!domain) {
            console.error('Domain is undefined');
            return;
        }

        // Find the website in the list
        var site = $scope.WebSitesList.find(function(website) {
            return website.domain === domain;
        });

        if (!site) {
            console.error('Website not found:', domain);
            return;
        }

        // Set loading state
        site.loadingWPSites = true;

        // Toggle visibility
        site.showWPSites = !site.showWPSites;
        
        // If we're hiding, just return
        if (!site.showWPSites) {
            site.loadingWPSites = false;
            return;
        }

        var config = {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = $.param({
            domain: domain
        });

        $http.post('/websites/fetchWPDetails', data, config)
            .then(function(response) {
                console.log('Response received:', response);
                if (response.data.status === 1 && response.data.fetchStatus === 1) {
                    site.wp_sites = response.data.sites || [];
                    // Initialize loading states for each WP site
                    site.wp_sites.forEach(function(wp) {
                        wp.loading = false;
                        wp.loadingPlugins = false;
                        wp.loadingTheme = false;
                    });
                    $("#listFail").hide();
                } else {
                    $("#listFail").fadeIn();
                    site.showWPSites = false;
                    $scope.errorMessage = response.data.error_message || 'Failed to fetch WordPress sites';
                    console.error('Error in response:', response.data.error_message);
                    new PNotify({
                        title: 'Error!',
                        text: response.data.error_message || 'Failed to fetch WordPress sites',
                        type: 'error'
                    });
                }
            })
            .catch(function(error) {
                console.error('Request failed:', error);
                site.showWPSites = false;
                $("#listFail").fadeIn();
                $scope.errorMessage = error.message || 'An error occurred while fetching WordPress sites';
                new PNotify({
                    title: 'Error!',
                    text: error.message || 'Could not connect to server',
                    type: 'error'
                });
            })
            .finally(function() {
                site.loadingWPSites = false;
            });
    };

    $scope.visitSite = function(wp) {
        var url = wp.url || wp.domain;
        if (!url) return;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        window.open(url, '_blank');
    };

    $scope.wpLogin = function(wpId) {
        window.open('/websites/AutoLogin?id=' + wpId, '_blank');
    };

    $scope.manageWP = function(wpId) {
        window.location.href = '/websites/WPHome?ID=' + wpId;
    };

    $scope.deleteWPSite = function(wp) {
        if (confirm('Are you sure you want to delete this WordPress site? This action cannot be undone.')) {
            window.location.href = '/websites/ListWPSites?DeleteID=' + wp.id;
        }
    };

    $scope.getFullUrl = function(url) {
        console.log('getFullUrl called with:', url);
        if (!url) {
            // If no URL is provided, try to use the domain
            if (this.wp && this.wp.domain) {
                url = this.wp.domain;
            } else {
                return '';
            }
        }
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return url;
        }
        return 'https://' + url;
    };


    $scope.updateSetting = function(wp, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: wp.id,
            setting: setting,
            value: wp[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && wp[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    wp.PPUsername = "";
                    wp.PPPassword = "";
                    $scope.currentWP = wp;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.UpdateWPSettings = function(wp) {
        $('#wordpresshomeloading').show();

        var url = "/websites/UpdateWPSettings";
        var data = {};

        if (wp.setting === "PasswordProtection") {
            data = {
                wpID: wp.id,
                setting: wp.setting,
                PPUsername: wp.PPUsername,
                PPPassword: wp.PPPassword
            };
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken'),
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            transformRequest: function(obj) {
                var str = [];
                for(var p in obj)
                    str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                return str.join("&");
            }
        };

        $http.post(url, data, config).then(function(response) {
            $('#wordpresshomeloading').hide();
            
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!',
                    type: 'success'
                });
                if (wp.setting === "PasswordProtection") {
                    location.reload();
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                if (wp.setting === "PasswordProtection") {
                    location.reload();
                }
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        });
    };

    $scope.togglePasswordProtection = function(wp) {
        console.log('togglePasswordProtection called for:', wp);
        console.log('Current password protection state:', wp.passwordProtection);
        
        if (wp.passwordProtection) {
            // Show modal for credentials
            console.log('Showing modal for credentials');
            wp.PPUsername = "";
            wp.PPPassword = "";
            $scope.currentWP = wp;
            console.log('Current WP set to:', $scope.currentWP);
            $('#passwordProtectionModal').modal('show');
        } else {
            // Disable password protection
            console.log('Disabling password protection');
            var data = {
                siteId: wp.id,
                setting: 'password-protection',
                value: 0
            };
            
            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            console.log('Sending request with data:', data);
            $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
                console.log('Received response:', response);
                if (!response.data.status) {
                    wp.passwordProtection = !wp.passwordProtection;
                    new PNotify({
                        title: 'Operation Failed!',
                        text: response.data.error_message || 'Failed to disable password protection',
                        type: 'error'
                    });
                } else {
                    new PNotify({
                        title: 'Success!',
                        text: 'Password protection disabled successfully.',
                        type: 'success'
                    });
                }
            }).catch(function(error) {
                console.error('Request failed:', error);
                wp.passwordProtection = !wp.passwordProtection;
                new PNotify({
                    title: 'Operation Failed!',
                    text: 'Could not connect to server.',
                    type: 'error'
                });
            });
        }
    };

    $scope.submitPasswordProtection = function() {
        console.log('submitPasswordProtection called');
        console.log('Current WP:', $scope.currentWP);
        
        if (!$scope.currentWP) {
            console.error('No WordPress site selected');
            new PNotify({
                title: 'Error!',
                text: 'No WordPress site selected.',
                type: 'error'
            });
            return;
        }

        if (!$scope.currentWP.PPUsername || !$scope.currentWP.PPPassword) {
            console.error('Missing username or password');
            new PNotify({
                title: 'Error!',
                text: 'Please provide both username and password',
                type: 'error'
            });
            return;
        }

        var data = {
            siteId: $scope.currentWP.id,
            setting: 'password-protection',
            value: 1,
            username: $scope.currentWP.PPUsername,
            password: $scope.currentWP.PPPassword
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log('Sending request with data:', data);
        $('#passwordProtectionModal').modal('hide');

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            console.log('Received response:', response);
            if (response.data.status) {
                new PNotify({
                    title: 'Success!',
                    text: 'Password protection enabled successfully!',
                    type: 'success'
                });
            } else {
                $scope.currentWP.passwordProtection = false;
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message || 'Failed to enable password protection',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            console.error('Request failed:', error);
            $scope.currentWP.passwordProtection = false;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server',
                type: 'error'
            });
        });
    };

    $scope.cyberPanelLoading = true;

    $scope.issueSSL = function (virtualHost) {
        $scope.cyberPanelLoading = false;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: virtualHost
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.SSL === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'SSL successfully issued.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        }


    };

    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {
        $scope.loading = true; // Set loading to true when starting search

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchWebsites";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
            $scope.loading = false; // Set loading to false on error
        });
    };

    $scope.ScanWordpressSite = function () {

        $('#cyberPanelLoading').show();


        var url = "/websites/ScanWordpressSite";

        var data = {}


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            $('#cyberPanelLoading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#cyberPanelLoading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };

    $scope.goToManage = function($event, domain) {
        $event.stopPropagation();
        window.location = '/websites/' + domain;
    };

    $scope.goToFileManager = function($event, domain) {
        $event.stopPropagation();
        window.location = '/filemanager/' + domain;
    };

});

/**
 * Created by usman on 7/26/17.
 */
function getCookie(name) {
    var cookieValue = null;
    var t = document.cookie;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}


var arry = []

function selectpluginJs(val) {
    $('#mysearch').hide()
    arry.push(val)

    // console.log(arry)
    document.getElementById('selJS').innerHTML = "";

    for (var i = 0; i < arry.length; i++) {
        $('#selJS').show()
        var mlm = '<span style="background-color: #12207a; color: #FFFFFF; padding: 5px;  border-radius: 30px"> ' + arry[i] + ' </span>&nbsp &nbsp'
        $('#selJS').append(mlm)
    }


}


var DeletePluginURL;

function DeletePluginBuucket(url) {
    DeletePluginURL = url;
}

function FinalDeletePluginBuucket() {
    window.location.href = DeletePluginURL;
}

var SPVal;

app.controller('WPAddNewPlugin', function ($scope, $http, $timeout, $window, $compile) {
    $scope.webSiteCreationLoading = true;

    $scope.SearchPluginName = function (val) {
        $scope.webSiteCreationLoading = false;
        SPVal = val;
        url = "/websites/SearchOnkeyupPlugin";

        var searchcontent = $scope.searchcontent;


        var data = {
            pluginname: searchcontent
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;

            if (response.data.status === 1) {
                if (SPVal == 'add') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option onclick="selectpluginJs(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        $('#mysearch').append(tml);
                    }
                } else if (SPVal == 'eidt') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option  ng-click="Addplugin(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        var temp = $compile(tml)($scope)
                        angular.element(document.getElementById('mysearch')).append(temp);
                    }

                }


            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.AddNewplugin = function () {

        url = "/websites/AddNewpluginAjax";

        var bucketname = $scope.PluginbucketName

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        var data = {
            config: arry,
            Name: bucketname
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Bucket created.',
                    type: 'success'
                });
                location.reload();
            } else {

                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.deletesPlgin = function (val) {

        url = "/websites/deletesPlgin";


        var data = {
            pluginname: val,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    }

    $scope.Addplugin = function (slug) {
        $('#mysearch').hide()

        url = "/websites/Addplugineidt";


        var data = {
            pluginname: slug,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }


    }

});

var domain_check = 0;

function checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        domain_check = 0;
        document.getElementById('Test_Domain').style.display = "block";
        document.getElementById('Own_Domain').style.display = "none";

    } else {
        document.getElementById('Test_Domain').style.display = "none";
        document.getElementById('Own_Domain').style.display = "block";
        domain_check = 1;
    }

    // alert(domain_check);
}

app.controller('createWordpress', function ($scope, $http, $timeout, $compile, $window) {
    $scope.webSiteCreationLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    // Password generation function
    $scope.randomPassword = function(length) {
        var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        var password = "";
        for (var i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    };

    // Initialize showPassword
    $scope.showPassword = false;

    var statusFile;

    $scope.createWordPresssite = function () {

        $scope.webSiteCreationLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;


        $scope.currentStatus = "Starting creation..";

        var apacheBackend = 0;

        if ($scope.apacheBackend === true) {
            apacheBackend = 1;
        } else {
            apacheBackend = 0
        }

        var package = $scope.packageForWebsite;
        var websiteOwner = $scope.websiteOwner;
        var WPtitle = $scope.WPtitle;

        // if (domain_check == 0) {
        //     var Part2_domainNameCreate = document.getElementById('Part2_domainNameCreate').value;
        //     var domainNameCreate = document.getElementById('TestDomainNameCreate').value + Part2_domainNameCreate;
        // }
        // if (domain_check == 1) {
        //
        //     var domainNameCreate = $scope.own_domainNameCreate;
        // }

        var domainNameCreate = $scope.domainNameCreate;


        var WPUsername = $scope.WPUsername;
        var adminEmail = $scope.adminEmail;
        var WPPassword = $scope.WPPassword;
        var WPVersions = $scope.WPVersions;
        var pluginbucket = $scope.pluginbucket;
        var autoupdates = $scope.autoupdates;
        var pluginupdates = $scope.pluginupdates;
        var themeupdates = $scope.themeupdates;

        if (domain_check == 0) {

            var path = "";

        }
        if (domain_check = 1) {

            var path = $scope.installPath;

        }


        var home = "1";

        if (typeof path != 'undefined') {
            home = "0";
        }

        //alert(domainNameCreate);
        var data = {

            title: WPtitle,
            domain: domainNameCreate,
            WPVersion: WPVersions,
            pluginbucket: pluginbucket,
            adminUser: WPUsername,
            Email: adminEmail,
            PasswordByPass: WPPassword,
            AutomaticUpdates: autoupdates,
            Plugins: pluginupdates,
            Themes: themeupdates,
            websiteOwner: websiteOwner,
            package: package,
            home: home,
            path: path,
            apacheBackend: apacheBackend
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        var url = "/websites/submitWorpressCreation";

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $scope.goBackDisable = false;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    };
    $scope.goBack = function () {
        $scope.webSiteCreationLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $scope.webSiteCreationLoading = false;
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }


});


//........... delete wp list
var FurlDeleteWP;

function DeleteWPNow(url) {
    FurlDeleteWP = url;
}

function FinalDeleteWPNow() {
    window.location.href = FurlDeleteWP;
}

var DeploytoProductionID;

function DeployToProductionInitial(vall) {
    DeploytoProductionID = vall;
}

// Simplified staging domain input - checkbox functionality removed

app.controller('WPsiteHome', function ($scope, $http, $timeout, $compile, $window) {
    var CheckBoxpasssword = 0;
    
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;
    $scope.searchIndex = 0;

    $(document).ready(function () {
        var checkstatus = document.getElementById("wordpresshome");
        if (checkstatus !== null) {
            $scope.LoadWPdata();
        }
    });

    $scope.LoadWPdata = function () {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/FetchWPdata";

        var data = {
            WPid: $('#WPid').html(),
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#WPVersion').text(response.data.ret_data.version);
                if (response.data.ret_data.lscache === 1) {
                    $('#lscache').prop('checked', true);
                }
                if (response.data.ret_data.debugging === 1) {
                    $('#debugging').prop('checked', true);
                }
                
                // Set search index state
                $scope.searchIndex = response.data.ret_data.searchIndex;
                
                if (response.data.ret_data.maintenanceMode === 1) {
                    $('#maintenanceMode').prop('checked', true);
                }
                if (response.data.ret_data.wpcron === 1) {
                    $('#wpcron').prop('checked', true);
                }
                if (response.data.ret_data.passwordprotection == 1) {
                    var dc = '<input type="checkbox" checked ng-click="UpdateWPSettings(\'PasswordProtection\')" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    var mp = $compile(dc)($scope);
                    angular.element(document.getElementById('prsswdprodata')).append(mp);
                    CheckBoxpasssword = 1;
                } else {
                    var dc = '<input type="checkbox" data-toggle="modal" data-target="#Passwordprotection" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    $('#prsswdprodata').append(dc);
                    CheckBoxpasssword = 0;
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            console.error('Failed to load WP data:', error);
        });
    };

    $scope.UpdateWPSettings = function (setting) {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/UpdateWPSettings";
        var data;

        if (setting === "PasswordProtection") {
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                PPUsername: CheckBoxpasssword == 0 ? $scope.PPUsername : '',
                PPPassword: CheckBoxpasssword == 0 ? $scope.PPPassword : ''
            };
        } else {
            var settingValue;
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                settingValue = $scope.searchIndex;
            } else {
                settingValue = $('#' + setting).is(":checked") ? 1 : 0;
            }
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                settingValue: settingValue
            };
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!',
                    type: 'success'
                });
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                // Revert the change on error
                if (setting === 'searchIndex') {
                    $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                }
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            // Revert the change on error
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
            }
            console.error('Failed to update setting:', error);
        });
    };

    $scope.GetCurrentPlugins = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentPlugins";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#PluginBody').html('');
                var plugins = JSON.parse(response.data.plugins);
                plugins.forEach(AddPlugins);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.GetCurrentThemes = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentThemes";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {

                $('#ThemeBody').html('');
                var themes = JSON.parse(response.data.themes);
                themes.forEach(AddThemes);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.UpdatePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdatePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Plugins in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeletePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeletePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Plugin in Background!',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    $scope.ChangeStatus = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/ChangeStatus";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Changed Plugin state Successfully !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    function AddPlugins(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddPluginToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdatePlugins(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger">Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeletePlugins(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-icon-left m-b-10" type="button">Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#PluginBody', temp)
    }

    $scope.UpdateThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdateThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Theme in background !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeleteThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeleteThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Theme in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    $scope.ChangeStatusThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            theme: theme,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/StatusThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Change Theme state in Bsckground!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    function AddThemes(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddThemeToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdateThemes(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger btn-sm"><i class="fas fa-sync-alt"></i> Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeleteThemes(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-icon-left m-b-10" type="button">Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#ThemeBody', temp)
    }

    $scope.CreateStagingNow = function () {
        $('#wordpresshomeloading').show();
        $('#stagingStatus').html('<i class="fas fa-spinner fa-pulse"></i> Starting staging site creation...');
        $('button[ng-click="CreateStagingNow()"]').prop('disabled', true).html('<i class="fas fa-spinner fa-pulse"></i> Creating Staging Site...');

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;


        $scope.currentStatus = "Starting creation Staging..";

        // Get the staging domain from the simplified input
        var domainNameCreate = $('#stagingDomainName').val() || $scope.stagingDomainName;
        var data = {
            StagingName: $('#stagingName').val(),
            StagingDomain: domainNameCreate,
            WPid: $('#WPid').html(),
        }
        var url = "/websites/CreateStagingNow";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> Could not connect to server</span>');
            $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            //$('#wordpresshomeloading').hide();

            if (response.data.abort === 1) {
                if (response.data.installStatus === 1) {

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;


                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();


                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    $scope.fetchstaging = function () {

        // Ensure DOM is ready
        $timeout(function() {
            // Check if the staging table exists
            if ($('#StagingBody').length === 0) {
                console.error('StagingBody table not found in DOM');
                return;
            }

            $('#wordpresshomeloading').show();
            $scope.wordpresshomeloading = false;

            var url = "/websites/fetchstaging";

            var data = {
                WPid: $('#WPid').html(),
            }

            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };


            $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


            function ListInitialDatas(response) {
                wordpresshomeloading = true;
                $('#wordpresshomeloading').hide();

                if (response.data.status === 1) {

                    //   $('#ThemeBody').html('');
                    // var themes = JSON.parse(response.data.themes);
                    // themes.forEach(AddThemes);

                    $('#StagingBody').html('');
                    console.log('Staging response:', response.data);
                    
                    try {
                        var staging = JSON.parse(response.data.wpsites);
                        console.log('Parsed staging data:', staging);
                        
                        if (staging && staging.length > 0) {
                            staging.forEach(function(site, index) {
                                console.log('Processing staging site ' + index + ':', site);
                                AddStagings(site, index, staging);
                            });
                        } else {
                            $('#StagingBody').html('<tr><td colspan="4" class="text-center">No staging sites found</td></tr>');
                        }
                    } catch (e) {
                        console.error('Error parsing staging data:', e);
                        $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error loading staging sites</td></tr>');
                    }

                } else {
                    console.error("Error from server:", response.data.error_message);
                    $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error: ' + response.data.error_message + '</td></tr>');
                }

            }

            function cantLoadInitialDatas(response) {
                $('#wordpresshomeloading').hide();
                console.error("Request failed:", response);
                $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Failed to load staging sites</td></tr>');
            }
        }, 100); // Small delay to ensure DOM is ready

    };

    $scope.fetchDatabase = function () {

        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;

        var url = "/websites/fetchDatabase";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#DB_Name').html(response.data.DataBaseName);
                $('#DB_User').html(response.data.DataBaseUser);
                $('#tableprefix').html(response.data.tableprefix);
            } else {
                alert("Error data.error_message:" + response.data.error_message)

            }
        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            alert("Error" + response)

        }

    };

    $scope.SaveUpdateConfig = function () {
        $('#wordpresshomeloading').show();
        var data = {
            AutomaticUpdates: $('#AutomaticUpdates').find(":selected").text(),
            Plugins: $('#Plugins').find(":selected").text(),
            Themes: $('#Themes').find(":selected").text(),
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/SaveUpdateConfig";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Update Configurations Sucessfully!.',
                    type: 'success'
                });
                $("#autoUpdateConfig").modal('hide');
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }
    };

    function AddStagings(value, index, array) {
        console.log('AddStagings function called with:', value);
        
        // Check if table element exists
        if ($('#stagingListBody').length === 0) {
            console.error('stagingListBody not found! Looking for StagingBody...');
            if ($('#StagingBody').length > 0) {
                console.log('Found StagingBody, using that instead');
                var tableSelector = '#StagingBody';
            } else {
                console.error('Neither stagingListBody nor StagingBody found!');
                console.log('Available table bodies:', $('tbody').map(function() { return this.id; }).get());
                return;
            }
        } else {
            var tableSelector = '#stagingListBody';
        }
        
        var stagingUrl = 'http://' + value.Domain;
        var createdDate = new Date().toLocaleDateString();
        
        var FinalMarkup = '<tr>';
        FinalMarkup += '<td><a href="/websites/WPHome?ID=' + value.id + '">' + value.name + '</a></td>';
        FinalMarkup += '<td><a href="' + stagingUrl + '" target="_blank">' + stagingUrl + '</a></td>';
        FinalMarkup += '<td>' + createdDate + '</td>';
        FinalMarkup += '<td>';
        FinalMarkup += '<button class="btn btn-sm btn-primary" onclick="DeployToProductionInitial(' + value.id + ')" data-toggle="modal" data-target="#DeployToProduction"><i class="fas fa-sync"></i> Sync to Production</button> ';
        FinalMarkup += '<button class="btn btn-sm btn-danger" onclick="deleteStagingGlobal(' + value.id + ')"><i class="fas fa-trash"></i> Delete</button>';
        FinalMarkup += '</td>';
        FinalMarkup += '</tr>';
        
        console.log('Appending to:', tableSelector);
        $(tableSelector).append(FinalMarkup);
        console.log('Rows in table after append:', $(tableSelector).find('tr').length);
    }

    $scope.FinalDeployToProduction = function () {

        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        var data = {
            WPid: $('#WPid').html(),
            StagingID: DeploytoProductionID
        }

        var url = "/websites/DeploytoProduction";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deploy To Production start!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }

    };


    $scope.CreateBackup = function () {
        $('#wordpresshomeloading').show();
        $('#createbackupbutton').prop('disabled', true).html('<i class="fas fa-spinner fa-pulse"></i> Creating Backup...');

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting creation Backups..";
        var data = {
            WPid: $('#WPid').html(),
            Backuptype: $('#backuptype').val()
        }
        var url = "/websites/WPCreateBackup";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Creating Backups!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            alert(response)

        }

    };


    $scope.installwpcore = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/installwpcore";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched..',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    $scope.dataintegrity = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/dataintegrity";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

});


var PluginsList = [];


function AddPluginToArray(cBox, name) {
    if (cBox.checked) {
        PluginsList.push(name);
        // alert(PluginsList);
    } else {
        const index = PluginsList.indexOf(name);
        if (index > -1) {
            PluginsList.splice(index, 1);
        }
        // alert(PluginsList);
    }
}

var ThemesList = [];

function AddThemeToArray(cBox, name) {
    if (cBox.checked) {
        ThemesList.push(name);
        // alert(ThemesList);
    } else {
        const index = ThemesList.indexOf(name);
        if (index > -1) {
            ThemesList.splice(index, 1);
        }
        // alert(ThemesList);
    }
}


function AppendToTable(table, markup) {
    $(table).append(markup);
}


//..................Restore Backup Home


app.controller('RestoreWPBackup', function ($scope, $http, $timeout, $window) {
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;


    $scope.checkmethode = function () {
        var val = $('#RestoreMethode').children("option:selected").val();
        if (val == 1) {
            $('#Newsitediv').show();
            $('#exinstingsitediv').hide();
        } else if (val == 0) {
            $('#exinstingsitediv').show();
            $('#Newsitediv').hide();
        } else {

        }
    };


    $scope.RestoreWPbackupNow = function () {
        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Start Restoring WordPress..";

        var Domain = $('#wprestoresubdirdomain').val()
        var path = $('#wprestoresubdirpath').val();
        var home = "1";

        if (typeof path != 'undefined' || path != '') {
            home = "0";
        }
        if (typeof path == 'undefined') {
            path = "";
        }


        var backuptype = $('#backuptype').html();
        var data;
        if (backuptype == "DataBase Backup") {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: '',
                path: path,
                home: home,
            }
        } else {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: Domain,
                path: path,
                home: home,
            }

        }

        var url = "/websites/RestoreWPbackupNow";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        // console.log(data)

        var d = $('#DesSite').children("option:selected").val();
        var c = $("input[name=Newdomain]").val();
        // if (d == -1 || c == "") {
        //     alert("Please Select Method of Backup Restore");
        // } else {
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        // }


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Restoring process starts!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $('#wordpresshomeloading').hide();
                $scope.wordpresshomeloading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    }

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            if (response.data.abort === 1) {
                $('#wordpresshomeloading').hide();

                if (response.data.installStatus === 1) {
                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    
                    // Re-enable buttons
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // For backup operations, refresh the backup list
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Backup created successfully!</span>');
                        if (typeof window.fetchBackupList === 'function') {
                            window.fetchBackupList();
                        }
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#backupStatus').text('');
                        }, 5000);
                    }
                    // For staging operations, refresh the staging list
                    else {
                        $('#stagingStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Staging site created successfully!</span>');
                        $scope.fetchstaging();
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#stagingStatus').text('');
                        }, 5000);
                    }


                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };
});


//.......................................Remote Backup

//........... delete DeleteBackupConfigNow

function DeleteBackupConfigNow(url) {
    window.location.href = url;
}

function DeleteRemoteBackupsiteNow(url) {
    window.location.href = url;
}

function DeleteBackupfileConfigNow(url) {
    window.location.href = url;
}


app.controller('RemoteBackupConfig', function ($scope, $http, $timeout, $window) {
    $scope.RemoteBackupLoading = true;
    $scope.SFTPBackUpdiv = true;

    $scope.EndpointURLdiv = true;
    $scope.Selectprovider = true;
    $scope.S3keyNamediv = true;
    $scope.Accesskeydiv = true;
    $scope.SecretKeydiv = true;
    $scope.SelectRemoteBackuptype = function () {
        var val = $scope.RemoteBackuptype;
        if (val == "SFTP") {
            $scope.SFTPBackUpdiv = false;
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        } else if (val == "S3") {
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = false;
            $scope.S3keyNamediv = false;
            $scope.Accesskeydiv = false;
            $scope.SecretKeydiv = false;
            $scope.SFTPBackUpdiv = true;
        } else {
            $scope.RemoteBackupLoading = true;
            $scope.SFTPBackUpdiv = true;

            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        }
    }

    $scope.SelectProvidertype = function () {
        $scope.EndpointURLdiv = true;
        var provider = $scope.Providervalue
        if (provider == 'Backblaze') {
            $scope.EndpointURLdiv = false;
        } else {
            $scope.EndpointURLdiv = true;
        }
    }

    $scope.SaveBackupConfig = function () {
        $scope.RemoteBackupLoading = false;
        var Hname = $scope.Hostname;
        var Uname = $scope.Username;
        var Passwd = $scope.Password;
        var path = $scope.path;
        var type = $scope.RemoteBackuptype;
        var Providervalue = $scope.Providervalue;
        var data;
        if (type == "SFTP") {

            data = {
                Hname: Hname,
                Uname: Uname,
                Passwd: Passwd,
                path: path,
                type: type
            }
        } else if (type == "S3") {
            if (Providervalue == "Backblaze") {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    EndUrl: $scope.EndpointURL,
                    type: type
                }
            } else {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    type: type
                }

            }

        }
        var url = "/websites/SaveBackupConfig";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    }

});

var UpdatescheduleID;
app.controller('BackupSchedule', function ($scope, $http, $timeout, $window) {
    $scope.BackupScheduleLoading = true;
    $scope.SaveBackupSchedule = function () {
        $scope.RemoteBackupLoading = false;
        var FileRetention = $scope.Fretention;
        var Backfrequency = $scope.Bfrequency;


        var data = {
            FileRetention: FileRetention,
            Backfrequency: Backfrequency,
            ScheduleName: $scope.ScheduleName,
            RemoteConfigID: $('#RemoteConfigID').html(),
            BackupType: $scope.BackupType
        }
        var url = "/websites/SaveBackupSchedule";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };


    $scope.getupdateid = function (ID) {
        UpdatescheduleID = ID;
    }

    $scope.UpdateRemoteschedules = function () {
        $scope.RemoteBackupLoading = false;
        var Frequency = $scope.RemoteFrequency;
        var fretention = $scope.RemoteFileretention;

        var data = {
            ScheduleID: UpdatescheduleID,
            Frequency: Frequency,
            FileRetention: fretention
        }
        var url = "/websites/UpdateRemoteschedules";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    };

    $scope.AddWPsiteforRemoteBackup = function () {
        $scope.RemoteBackupLoading = false;


        var data = {
            WpsiteID: $('#Wpsite').val(),
            RemoteScheduleID: $('#RemoteScheduleID').html()
        }
        var url = "/websites/AddWPsiteforRemoteBackup";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };
});
/* Java script code to create account */

var website_create_domain_check = 0;

function website_create_checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        website_create_domain_check = 0;
        document.getElementById('Website_Create_Test_Domain').style.display = "block";
        document.getElementById('Website_Create_Own_Domain').style.display = "none";

    } else {
        document.getElementById('Website_Create_Test_Domain').style.display = "none";
        document.getElementById('Website_Create_Own_Domain').style.display = "block";
        website_create_domain_check = 1;
    }

    // alert(domain_check);
}

app.controller('createWebsite', function ($scope, $http, $timeout, $window) {

    $scope.webSiteCreationLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    var statusFile;

    $scope.createWebsite = function () {

        $scope.webSiteCreationLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation..";

        var ssl, dkimCheck, openBasedir, mailDomain, apacheBackend;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        if ($scope.apacheBackend === true) {
            apacheBackend = 1;
        } else {
            apacheBackend = 0
        }

        if ($scope.dkimCheck === true) {
            dkimCheck = 1;
        } else {
            dkimCheck = 0
        }

        if ($scope.openBasedir === true) {
            openBasedir = 1;
        } else {
            openBasedir = 0
        }

        if ($scope.mailDomain === true) {
            mailDomain = 1;
        } else {
            mailDomain = 0
        }

        url = "/websites/submitWebsiteCreation";

        var package = $scope.packageForWebsite;

        // if (website_create_domain_check == 0) {
        //     var Part2_domainNameCreate = document.getElementById('Part2_domainNameCreate').value;
        //     var domainName = document.getElementById('TestDomainNameCreate').value + Part2_domainNameCreate;
        // }
        // if (website_create_domain_check == 1) {
        //     var domainName = $scope.domainNameCreate;
        // }
        var domainName = $scope.domainNameCreate;

        var adminEmail = $scope.adminEmail;
        var phpSelection = $scope.phpSelection;
        var websiteOwner = $scope.websiteOwner;


        var data = {
            package: package,
            domainName: domainName,
            adminEmail: adminEmail,
            phpSelection: phpSelection,
            ssl: ssl,
            websiteOwner: websiteOwner,
            dkimCheck: dkimCheck,
            openBasedir: openBasedir,
            mailDomain: mailDomain,
            apacheBackend: apacheBackend
        };


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createWebSiteStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.webSiteCreationLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };
    $scope.goBack = function () {
        $scope.webSiteCreationLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

});
/* Java script code to create account ends here */

/* Java script code to list accounts */

$("#listFail").hide();


app.controller('listWebsites', function ($scope, $http, $window) {
    $scope.web = {};
    $scope.WebSitesList = [];
    $scope.loading = true; // Add loading state
    $scope.expandedSites = {}; // Track which sites are expanded

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    // Function to toggle site expansion
    $scope.toggleSite = function(site) {
        if (!$scope.expandedSites[site.domain]) {
            $scope.expandedSites[site.domain] = true;
            site.loading = true;
            // You can add any data fetching logic here if needed
            setTimeout(function() {
                site.loading = false;
                $scope.$apply();
            }, 500);
        } else {
            $scope.expandedSites[site.domain] = false;
        }
    };

    // Function to check if site is expanded
    $scope.isExpanded = function(siteId) {
        return $scope.expandedSites[siteId];
    };

    // Function to check if site data is loaded
    $scope.isDataLoaded = function(site) {
        return site.version !== undefined;
    };

    // Initial fetch of websites
    $scope.getFurtherWebsitesFromDB = function () {
        $scope.loading = true; // Set loading to true when starting fetch
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };

        var dataurl = "/websites/fetchWebsitesList";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $("#listFail").hide();
                // Expand the first site by default
                if ($scope.WebSitesList.length > 0) {
                    $scope.expandedSites[$scope.WebSitesList[0].domain] = true;
                }
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            $("#listFail").fadeIn();
            $scope.errorMessage = error.message || 'An error occurred while fetching websites';
            $scope.loading = false; // Set loading to false on error
        });
    };

    // Call it immediately
    $scope.getFurtherWebsitesFromDB();

    $scope.showWPSites = function(domain) {
        console.log('showWPSites called for domain:', domain);
        
        // Make sure domain is defined
        if (!domain) {
            console.error('Domain is undefined');
            return;
        }

        // Find the website in the list
        var site = $scope.WebSitesList.find(function(website) {
            return website.domain === domain;
        });

        if (!site) {
            console.error('Website not found:', domain);
            return;
        }

        // Set loading state
        site.loadingWPSites = true;

        // Toggle visibility
        site.showWPSites = !site.showWPSites;
        
        // If we're hiding, just return
        if (!site.showWPSites) {
            site.loadingWPSites = false;
            return;
        }

        var config = {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = $.param({
            domain: domain
        });

        $http.post('/websites/fetchWPDetails', data, config)
            .then(function(response) {
                console.log('Response received:', response);
                if (response.data.status === 1 && response.data.fetchStatus === 1) {
                    site.wp_sites = response.data.sites || [];
                    // Initialize loading states for each WP site
                    site.wp_sites.forEach(function(wp) {
                        wp.loading = false;
                        wp.loadingPlugins = false;
                        wp.loadingTheme = false;
                    });
                    $("#listFail").hide();
                } else {
                    $("#listFail").fadeIn();
                    site.showWPSites = false;
                    $scope.errorMessage = response.data.error_message || 'Failed to fetch WordPress sites';
                    console.error('Error in response:', response.data.error_message);
                    new PNotify({
                        title: 'Error!',
                        text: response.data.error_message || 'Failed to fetch WordPress sites',
                        type: 'error'
                    });
                }
            })
            .catch(function(error) {
                console.error('Request failed:', error);
                site.showWPSites = false;
                $("#listFail").fadeIn();
                $scope.errorMessage = error.message || 'An error occurred while fetching WordPress sites';
                new PNotify({
                    title: 'Error!',
                    text: error.message || 'Could not connect to server',
                    type: 'error'
                });
            })
            .finally(function() {
                site.loadingWPSites = false;
            });
    };

    $scope.visitSite = function(wp) {
        var url = wp.url || wp.domain;
        if (!url) return;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        window.open(url, '_blank');
    };

    $scope.wpLogin = function(wpId) {
        window.open('/websites/wpLogin?wpID=' + wpId, '_blank');
    };

    $scope.manageWP = function(wpId) {
        window.location.href = '/websites/WPHome?ID=' + wpId;
    };

    $scope.deleteWPSite = function(wp) {
        if (confirm('Are you sure you want to delete this WordPress site? This action cannot be undone.')) {
            window.location.href = '/websites/ListWPSites?DeleteID=' + wp.id;
        }
    };

    $scope.getFullUrl = function(url) {
        console.log('getFullUrl called with:', url);
        if (!url) {
            // If no URL is provided, try to use the domain
            if (this.wp && this.wp.domain) {
                url = this.wp.domain;
            } else {
                return '';
            }
        }
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return url;
        }
        return 'https://' + url;
    };



    $scope.updateSetting = function(wp, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: wp.id,
            setting: setting,
            value: wp[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && wp[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    wp.PPUsername = "";
                    wp.PPPassword = "";
                    $scope.currentWP = wp;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.UpdateWPSettings = function(wp) {
        $('#wordpresshomeloading').show();

        var url = "/websites/UpdateWPSettings";
        var data = {};

        if (wp.setting === "PasswordProtection") {
            data = {
                wpID: wp.id,
                setting: wp.setting,
                PPUsername: wp.PPUsername,
                PPPassword: wp.PPPassword
            };
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken'),
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            transformRequest: function(obj) {
                var str = [];
                for(var p in obj)
                    str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                return str.join("&");
            }
        };

        $http.post(url, data, config).then(function(response) {
            $('#wordpresshomeloading').hide();
            
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!',
                    type: 'success'
                });
                if (wp.setting === "PasswordProtection") {
                    location.reload();
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                if (wp.setting === "PasswordProtection") {
                    location.reload();
                }
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        });
    };

    $scope.togglePasswordProtection = function(wp) {
        console.log('togglePasswordProtection called for:', wp);
        console.log('Current password protection state:', wp.passwordProtection);
        
        if (wp.passwordProtection) {
            // Show modal for credentials
            console.log('Showing modal for credentials');
            wp.PPUsername = "";
            wp.PPPassword = "";
            $scope.currentWP = wp;
            console.log('Current WP set to:', $scope.currentWP);
            $('#passwordProtectionModal').modal('show');
        } else {
            // Disable password protection
            console.log('Disabling password protection');
            var data = {
                siteId: wp.id,
                setting: 'password-protection',
                value: 0
            };
            
            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            console.log('Sending request with data:', data);
            $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
                console.log('Received response:', response);
                if (!response.data.status) {
                    wp.passwordProtection = !wp.passwordProtection;
                    new PNotify({
                        title: 'Operation Failed!',
                        text: response.data.error_message || 'Failed to disable password protection',
                        type: 'error'
                    });
                } else {
                    new PNotify({
                        title: 'Success!',
                        text: 'Password protection disabled successfully.',
                        type: 'success'
                    });
                }
            }).catch(function(error) {
                console.error('Request failed:', error);
                wp.passwordProtection = !wp.passwordProtection;
                new PNotify({
                    title: 'Operation Failed!',
                    text: 'Could not connect to server.',
                    type: 'error'
                });
            });
        }
    };

    $scope.submitPasswordProtection = function() {
        console.log('submitPasswordProtection called');
        console.log('Current WP:', $scope.currentWP);
        
        if (!$scope.currentWP) {
            console.error('No WordPress site selected');
            new PNotify({
                title: 'Error!',
                text: 'No WordPress site selected.',
                type: 'error'
            });
            return;
        }

        if (!$scope.currentWP.PPUsername || !$scope.currentWP.PPPassword) {
            console.error('Missing username or password');
            new PNotify({
                title: 'Error!',
                text: 'Please provide both username and password',
                type: 'error'
            });
            return;
        }

        var data = {
            siteId: $scope.currentWP.id,
            setting: 'password-protection',
            value: 1,
            username: $scope.currentWP.PPUsername,
            password: $scope.currentWP.PPPassword
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log('Sending request with data:', data);
        $('#passwordProtectionModal').modal('hide');

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            console.log('Received response:', response);
            if (response.data.status) {
                new PNotify({
                    title: 'Success!',
                    text: 'Password protection enabled successfully!',
                    type: 'success'
                });
            } else {
                $scope.currentWP.passwordProtection = false;
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message || 'Failed to enable password protection',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            console.error('Request failed:', error);
            $scope.currentWP.passwordProtection = false;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server',
                type: 'error'
            });
        });
    };

    $scope.cyberPanelLoading = true;

    $scope.issueSSL = function (virtualHost) {
        $scope.cyberPanelLoading = false;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: virtualHost
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.SSL === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'SSL successfully issued.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        }


    };

    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {
        $scope.loading = true; // Set loading to true when starting search

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchWebsites";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
            $scope.loading = false; // Set loading to false on error
        });
    };

    $scope.ScanWordpressSite = function () {

        $('#cyberPanelLoading').show();


        var url = "/websites/ScanWordpressSite";

        var data = {}


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            $('#cyberPanelLoading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#cyberPanelLoading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };

});

app.controller('listChildDomainsMain', function ($scope, $http, $timeout) {

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    $scope.getFurtherWebsitesFromDB = function () {

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };


        dataurl = "/websites/fetchChildDomainsMain";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            if (response.data.listWebSiteStatus === 1) {

                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $scope.clients = JSON.parse(response.data.data);
                $("#listFail").hide();
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;

            }
        }

        function cantLoadInitialData(response) {
        }


    };
    $scope.getFurtherWebsitesFromDB();

    $scope.cyberPanelLoading = true;

    $scope.issueSSL = function (virtualHost) {
        $scope.cyberPanelLoading = false;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: virtualHost
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.SSL === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'SSL successfully issued.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        }


    };

    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {

        $scope.cyberPanelLoading = false;

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchChilds";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.listWebSiteStatus === 1) {

                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
        }

        function cantLoadInitialData(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
        }


    };

    $scope.initConvert = function (virtualHost) {
        $scope.domainName = virtualHost;
    };

    var statusFile;

    $scope.installationProgress = true;

    $scope.convert = function () {

        $scope.cyberPanelLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation..";

        var ssl, dkimCheck, openBasedir;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        if ($scope.dkimCheck === true) {
            dkimCheck = 1;
        } else {
            dkimCheck = 0
        }

        if ($scope.openBasedir === true) {
            openBasedir = 1;
        } else {
            openBasedir = 0
        }

        url = "/websites/convertDomainToSite";


        var data = {
            package: $scope.packageForWebsite,
            domainName: $scope.domainName,
            adminEmail: $scope.adminEmail,
            phpSelection: $scope.phpSelection,
            websiteOwner: $scope.websiteOwner,
            ssl: ssl,
            dkimCheck: dkimCheck,
            openBasedir: openBasedir
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createWebSiteStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.cyberPanelLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.goBackDisable = false;

                $scope.currentStatus = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.cyberPanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }


    };
    $scope.goBack = function () {
        $scope.cyberPanelLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.cyberPanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.cyberPanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $scope.currentStatus = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.cyberPanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }


    }

    var DeleteDomain;
    $scope.DeleteDocRoot = false;
    $scope.deleteDomainInit = function (childDomainForDeletion) {
        DeleteDomain = childDomainForDeletion;
        $scope.DeleteDocRoot = false;
    };

    $scope.deleteChildDomain = function () {
        console.log("Delete child domain called for:", DeleteDomain);
        console.log("Delete doc root:", $scope.DeleteDocRoot);
        
        $scope.cyberPanelLoading = false;
        url = "/websites/submitDomainDeletion";

        var data = {
            websiteName: DeleteDomain,
            DeleteDocRoot: $scope.DeleteDocRoot
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log("Sending delete request with data:", data);
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            console.log("Delete response received:", response.data);
            $scope.cyberPanelLoading = true;
            if (response.data.websiteDeleteStatus === 1) {
                console.log("Delete successful");
                new PNotify({
                    title: 'Success!',
                    text: 'Child Domain successfully deleted.',
                    type: 'success'
                });
                $('#DeleteChild').modal('hide');
                $('.modal-backdrop').remove();
                $scope.DeleteDocRoot = false;
                $scope.getFurtherWebsitesFromDB();
            } else {
                console.log("Delete failed:", response.data.error_message);
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            console.log("Delete request failed:", response);
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });

        }

    };

});

/* Java script code to list accounts ends here */


/* Java script code to delete Website */


$("#websiteDeleteFailure").hide();
$("#websiteDeleteSuccess").hide();

$("#deleteWebsiteButton").hide();
$("#deleteLoading").hide();

app.controller('deleteWebsiteControl', function ($scope, $http) {


    $scope.deleteWebsite = function () {

        $("#deleteWebsiteButton").fadeIn();


    };

    $scope.deleteWebsiteFinal = function () {

        $("#deleteLoading").show();

        var websiteName = $scope.websiteToBeDeleted;


        url = "/websites/submitWebsiteDeletion";

        var data = {
            websiteName: websiteName
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.websiteDeleteStatus === 0) {
                $scope.errorMessage = response.data.error_message;
                $("#websiteDeleteFailure").fadeIn();
                $("#websiteDeleteSuccess").hide();
                $("#deleteWebsiteButton").hide();


                $("#deleteLoading").hide();

            } else {
                $("#websiteDeleteFailure").hide();
                $("#websiteDeleteSuccess").fadeIn();
                $("#deleteWebsiteButton").hide();
                $scope.deletedWebsite = websiteName;
                $("#deleteLoading").hide();

            }


        }

        function cantLoadInitialDatas(response) {
        }


    };

});


/**
 * Created by usman on 7/26/17.
 */
function getCookie(name) {
    var cookieValue = null;
    var t = document.cookie;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}


var arry = []

function selectpluginJs(val) {
    $('#mysearch').hide()
    arry.push(val)

    // console.log(arry)
    document.getElementById('selJS').innerHTML = "";

    for (var i = 0; i < arry.length; i++) {
        $('#selJS').show()
        var mlm = '<span style="background-color: #12207a; color: #FFFFFF; padding: 5px;  border-radius: 30px"> ' + arry[i] + ' </span>&nbsp &nbsp'
        $('#selJS').append(mlm)
    }


}


var DeletePluginURL;

function DeletePluginBuucket(url) {
    DeletePluginURL = url;
}

function FinalDeletePluginBuucket() {
    window.location.href = DeletePluginURL;
}

var SPVal;

app.controller('WPAddNewPlugin', function ($scope, $http, $timeout, $window, $compile) {
    $scope.webSiteCreationLoading = true;

    $scope.SearchPluginName = function (val) {
        $scope.webSiteCreationLoading = false;
        SPVal = val;
        url = "/websites/SearchOnkeyupPlugin";

        var searchcontent = $scope.searchcontent;


        var data = {
            pluginname: searchcontent
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;

            if (response.data.status === 1) {
                if (SPVal == 'add') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option onclick="selectpluginJs(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        $('#mysearch').append(tml);
                    }
                } else if (SPVal == 'eidt') {
                    $('#mysearch').show()
                    document.getElementById('mysearch').innerHTML = "";
                    var res = response.data.plugns.plugins
                    // console.log(res);
                    for (i = 0; i <= res.length; i++) {
                        //
                        var tml = '<option  ng-click="Addplugin(\'' + res[i].slug + '\')" style="  border-bottom: 1px solid  rgba(90, 91, 92, 0.5); padding: 5px; " value="' + res[i].slug + '">' + res[i].name + '</option> <br>';
                        var temp = $compile(tml)($scope)
                        angular.element(document.getElementById('mysearch')).append(temp);
                    }

                }


            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.AddNewplugin = function () {

        url = "/websites/AddNewpluginAjax";

        var bucketname = $scope.PluginbucketName

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        var data = {
            config: arry,
            Name: bucketname
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Bucket created.',
                    type: 'success'
                });
                location.reload();
            } else {

                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }
    }

    $scope.deletesPlgin = function (val) {

        url = "/websites/deletesPlgin";


        var data = {
            pluginname: val,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    }

    $scope.Addplugin = function (slug) {
        $('#mysearch').hide()

        url = "/websites/Addplugineidt";


        var data = {
            pluginname: slug,
            pluginbBucketID: $('#pluginbID').html()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                location.reload();

            } else {

                // $scope.errorMessage = response.data.error_message;
                alert("Status not = 1: Error..." + response.data.error_message)
            }


        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }


    }

});

var domain_check = 0;

function checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        domain_check = 0;
        document.getElementById('Test_Domain').style.display = "block";
        document.getElementById('Own_Domain').style.display = "none";

    } else {
        document.getElementById('Test_Domain').style.display = "none";
        document.getElementById('Own_Domain').style.display = "block";
        domain_check = 1;
    }

    // alert(domain_check);
}

app.controller('createWordpress', function ($scope, $http, $timeout, $compile, $window) {
    $scope.webSiteCreationLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    // Password generation function
    $scope.randomPassword = function(length) {
        var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        var password = "";
        for (var i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    };

    // Initialize showPassword
    $scope.showPassword = false;

    var statusFile;

    $scope.createWordPresssite = function () {

        $scope.webSiteCreationLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;


        $scope.currentStatus = "Starting creation..";

        var apacheBackend = 0;

        if ($scope.apacheBackend === true) {
            apacheBackend = 1;
        } else {
            apacheBackend = 0
        }

        var package = $scope.packageForWebsite;
        var websiteOwner = $scope.websiteOwner;
        var WPtitle = $scope.WPtitle;

        // if (domain_check == 0) {
        //     var Part2_domainNameCreate = document.getElementById('Part2_domainNameCreate').value;
        //     var domainNameCreate = document.getElementById('TestDomainNameCreate').value + Part2_domainNameCreate;
        // }
        // if (domain_check == 1) {
        //
        //     var domainNameCreate = $scope.own_domainNameCreate;
        // }

        var domainNameCreate = $scope.domainNameCreate;


        var WPUsername = $scope.WPUsername;
        var adminEmail = $scope.adminEmail;
        var WPPassword = $scope.WPPassword;
        var WPVersions = $scope.WPVersions;
        var pluginbucket = $scope.pluginbucket;
        var autoupdates = $scope.autoupdates;
        var pluginupdates = $scope.pluginupdates;
        var themeupdates = $scope.themeupdates;

        if (domain_check == 0) {

            var path = "";

        }
        if (domain_check = 1) {

            var path = $scope.installPath;

        }


        var home = "1";

        if (typeof path != 'undefined') {
            home = "0";
        }

        //alert(domainNameCreate);
        var data = {

            title: WPtitle,
            domain: domainNameCreate,
            WPVersion: WPVersions,
            pluginbucket: pluginbucket,
            adminUser: WPUsername,
            Email: adminEmail,
            PasswordByPass: WPPassword,
            AutomaticUpdates: autoupdates,
            Plugins: pluginupdates,
            Themes: themeupdates,
            websiteOwner: websiteOwner,
            package: package,
            home: home,
            path: path,
            apacheBackend: apacheBackend
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        var url = "/websites/submitWorpressCreation";

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.webSiteCreationLoading = true;
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $scope.goBackDisable = false;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {

            alert("Error..." + response)

        }

    };
    $scope.goBack = function () {
        $scope.webSiteCreationLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.webSiteCreationLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $scope.webSiteCreationLoading = false;
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }


});


//........... delete wp list
var FurlDeleteWP;

function DeleteWPNow(url) {
    FurlDeleteWP = url;
}

function FinalDeleteWPNow() {
    window.location.href = FurlDeleteWP;
}

var DeploytoProductionID;

function DeployToProductionInitial(vall) {
    DeploytoProductionID = vall;
}

// Simplified staging domain input - checkbox functionality removed

app.controller('WPsiteHome', function ($scope, $http, $timeout, $compile, $window) {
    var CheckBoxpasssword = 0;
    
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;
    $scope.searchIndex = 0;

    $(document).ready(function () {
        var checkstatus = document.getElementById("wordpresshome");
        if (checkstatus !== null) {
            $scope.LoadWPdata();
        }
    });

    $scope.LoadWPdata = function () {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/FetchWPdata";

        var data = {
            WPid: $('#WPid').html(),
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#WPVersion').text(response.data.ret_data.version);
                if (response.data.ret_data.lscache === 1) {
                    $('#lscache').prop('checked', true);
                }
                if (response.data.ret_data.debugging === 1) {
                    $('#debugging').prop('checked', true);
                }
                
                // Set search index state
                $scope.searchIndex = response.data.ret_data.searchIndex;
                
                if (response.data.ret_data.maintenanceMode === 1) {
                    $('#maintenanceMode').prop('checked', true);
                }
                if (response.data.ret_data.wpcron === 1) {
                    $('#wpcron').prop('checked', true);
                }
                if (response.data.ret_data.passwordprotection == 1) {
                    var dc = '<input type="checkbox" checked ng-click="UpdateWPSettings(\'PasswordProtection\')" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    var mp = $compile(dc)($scope);
                    angular.element(document.getElementById('prsswdprodata')).append(mp);
                    CheckBoxpasssword = 1;
                } else {
                    var dc = '<input type="checkbox" data-toggle="modal" data-target="#Passwordprotection" class="custom-control-input" id="passwdprotection"><label class="custom-control-label" for="passwdprotection"></label>';
                    $('#prsswdprodata').append(dc);
                    CheckBoxpasssword = 0;
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            console.error('Failed to load WP data:', error);
        });
    };

    $scope.UpdateWPSettings = function (setting) {
        $scope.wordpresshomeloading = false;
        $('#wordpresshomeloading').show();

        var url = "/websites/UpdateWPSettings";
        var data;

        if (setting === "PasswordProtection") {
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                PPUsername: CheckBoxpasssword == 0 ? $scope.PPUsername : '',
                PPPassword: CheckBoxpasssword == 0 ? $scope.PPPassword : ''
            };
        } else {
            var settingValue;
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                settingValue = $scope.searchIndex;
            } else {
                settingValue = $('#' + setting).is(":checked") ? 1 : 0;
            }
            data = {
                WPid: $('#WPid').html(),
                setting: setting,
                settingValue: settingValue
            };
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(function(response) {
            $scope.wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!',
                    type: 'success'
                });
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                // Revert the change on error
                if (setting === 'searchIndex') {
                    $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
                }
                if (setting === "PasswordProtection") {
                    location.reload();
                }
            }
        }, function(error) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            // Revert the change on error
            if (setting === 'searchIndex') {
                $scope.searchIndex = $scope.searchIndex === 1 ? 0 : 1;
            }
            console.error('Failed to update setting:', error);
        });
    };

    $scope.GetCurrentPlugins = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentPlugins";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#PluginBody').html('');
                var plugins = JSON.parse(response.data.plugins);
                plugins.forEach(AddPlugins);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.GetCurrentThemes = function () {
        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;

        var url = "/websites/GetCurrentThemes";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {

                $('#ThemeBody').html('');
                var themes = JSON.parse(response.data.themes);
                themes.forEach(AddThemes);

            } else {
                alert("Error:" + response.data.error_message)

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.webSiteCreationLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.UpdatePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdatePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Plugins in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeletePlugins = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            pluginarray: PluginsList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeletePlugins";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Plugin in Background!',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    $scope.ChangeStatus = function (plugin) {
        $('#wordpresshomeloading').show();
        var data = {
            plugin: plugin,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/ChangeStatus";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Changed Plugin state Successfully !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    }

    function AddPlugins(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddPluginToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatus(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdatePlugins(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger">Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeletePlugins(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-icon-left m-b-10" type="button">Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#PluginBody', temp)
    }

    $scope.UpdateThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/UpdateThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Updating Theme in background !.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }


    };

    $scope.DeleteThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            Theme: theme,
            Themearray: ThemesList,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/DeleteThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deleting Theme in Background!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    $scope.ChangeStatusThemes = function (theme) {
        $('#wordpresshomeloading').show();
        var data = {
            theme: theme,
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/StatusThemes";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Change Theme state in Bsckground!.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    function AddThemes(value, index, array) {
        var FinalMarkup = '<tr>'
        FinalMarkup = FinalMarkup + '<td><input onclick="AddThemeToArray(this,\'' + value.name + '\')" type="checkbox" id="' + value.name + '"><label for="' + value.name + '"></label></td>';
        for (let x in value) {
            if (x === 'status') {
                if (value[x] === 'inactive') {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State"><label for="' + value.name + 'State"></label></div></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><div ng-click="ChangeStatusThemes(\'' + value.name + '\')" class="form-check form-check-inline switch"><input type="checkbox" id="' + value.name + 'State" checked=""><label for="' + value.name + 'State"></label></div></td>';
                }
            } else if (x === 'update') {
                if (value[x] === 'none') {
                    FinalMarkup = FinalMarkup + '<td><span class="label label-success">Upto Date</span></td>';
                } else {
                    FinalMarkup = FinalMarkup + '<td><button ng-click="UpdateThemes(\'' + value.name + '\')" aria-label="" type="button" class="btn btn-outline-danger btn-sm"><i class="fas fa-sync-alt"></i> Update</button></td>';
                }
            } else {
                FinalMarkup = FinalMarkup + '<td>' + value[x] + "</td>";
            }
        }
        FinalMarkup = FinalMarkup + '<td><button ng-click="DeleteThemes(\'' + value.name + '\')" aria-label="" class="btn btn-danger btn-icon-left m-b-10" type="button">Delete</button></td>'
        FinalMarkup = FinalMarkup + '</tr>'
        var temp = $compile(FinalMarkup)($scope)
        AppendToTable('#ThemeBody', temp)
    }

    $scope.CreateStagingNow = function () {
        $('#wordpresshomeloading').show();
        $('#stagingStatus').html('<i class="fas fa-spinner fa-pulse"></i> Starting staging site creation...');
        $('button[ng-click="CreateStagingNow()"]').prop('disabled', true).html('<i class="fas fa-spinner fa-pulse"></i> Creating Staging Site...');

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;


        $scope.currentStatus = "Starting creation Staging..";

        // Get the staging domain from the simplified input
        var domainNameCreate = $('#stagingDomainName').val() || $scope.stagingDomainName;
        var data = {
            StagingName: $('#stagingName').val(),
            StagingDomain: domainNameCreate,
            WPid: $('#WPid').html(),
        }
        var url = "/websites/CreateStagingNow";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> Could not connect to server</span>');
            $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            //$('#wordpresshomeloading').hide();

            if (response.data.abort === 1) {
                if (response.data.installStatus === 1) {

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;


                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();


                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    $scope.fetchstaging = function () {

        // Ensure DOM is ready
        $timeout(function() {
            // Check if the staging table exists
            if ($('#StagingBody').length === 0) {
                console.error('StagingBody table not found in DOM');
                return;
            }

            $('#wordpresshomeloading').show();
            $scope.wordpresshomeloading = false;

            var url = "/websites/fetchstaging";

            var data = {
                WPid: $('#WPid').html(),
            }

            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };


            $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


            function ListInitialDatas(response) {
                wordpresshomeloading = true;
                $('#wordpresshomeloading').hide();

                if (response.data.status === 1) {

                    //   $('#ThemeBody').html('');
                    // var themes = JSON.parse(response.data.themes);
                    // themes.forEach(AddThemes);

                    $('#StagingBody').html('');
                    console.log('Staging response:', response.data);
                    
                    try {
                        var staging = JSON.parse(response.data.wpsites);
                        console.log('Parsed staging data:', staging);
                        
                        if (staging && staging.length > 0) {
                            staging.forEach(function(site, index) {
                                console.log('Processing staging site ' + index + ':', site);
                                AddStagings(site, index, staging);
                            });
                        } else {
                            $('#StagingBody').html('<tr><td colspan="4" class="text-center">No staging sites found</td></tr>');
                        }
                    } catch (e) {
                        console.error('Error parsing staging data:', e);
                        $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error loading staging sites</td></tr>');
                    }

                } else {
                    console.error("Error from server:", response.data.error_message);
                    $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Error: ' + response.data.error_message + '</td></tr>');
                }

            }

            function cantLoadInitialDatas(response) {
                $('#wordpresshomeloading').hide();
                console.error("Request failed:", response);
                $('#StagingBody').html('<tr><td colspan="4" class="text-center text-danger">Failed to load staging sites</td></tr>');
            }
        }, 100); // Small delay to ensure DOM is ready

    };

    $scope.fetchDatabase = function () {

        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;

        var url = "/websites/fetchDatabase";

        var data = {
            WPid: $('#WPid').html(),
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                $('#DB_Name').html(response.data.DataBaseName);
                $('#DB_User').html(response.data.DataBaseUser);
                $('#tableprefix').html(response.data.tableprefix);
            } else {
                alert("Error data.error_message:" + response.data.error_message)

            }
        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            alert("Error" + response)

        }

    };

    $scope.SaveUpdateConfig = function () {
        $('#wordpresshomeloading').show();
        var data = {
            AutomaticUpdates: $('#AutomaticUpdates').find(":selected").text(),
            Plugins: $('#Plugins').find(":selected").text(),
            Themes: $('#Themes').find(":selected").text(),
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/SaveUpdateConfig";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Update Configurations Sucessfully!.',
                    type: 'success'
                });
                $("#autoUpdateConfig").modal('hide');
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }
    };

    function AddStagings(value, index, array) {
        var stagingUrl = 'http://' + value.Domain;
        var createdDate = new Date().toLocaleDateString();
        
        var FinalMarkup = '<tr>';
        FinalMarkup += '<td><a href="/websites/WPHome?ID=' + value.id + '">' + value.name + '</a></td>';
        FinalMarkup += '<td><a href="' + stagingUrl + '" target="_blank">' + stagingUrl + '</a></td>';
        FinalMarkup += '<td>' + createdDate + '</td>';
        FinalMarkup += '<td>';
        FinalMarkup += '<button class="btn btn-sm btn-primary" onclick="DeployToProductionInitial(' + value.id + ')" data-toggle="modal" data-target="#DeployToProduction"><i class="fas fa-sync"></i> Sync to Production</button> ';
        FinalMarkup += '<button class="btn btn-sm btn-danger" onclick="deleteStagingGlobal(' + value.id + ')"><i class="fas fa-trash"></i> Delete</button>';
        FinalMarkup += '</td>';
        FinalMarkup += '</tr>';
        
        console.log('Appending to #stagingListBody');
        if ($('#stagingListBody').length === 0) {
            console.error('stagingListBody not found! Looking for StagingBody...');
            if ($('#StagingBody').length > 0) {
                console.log('Found StagingBody, using that instead');
                $('#StagingBody').append(FinalMarkup);
            } else {
                console.error('Neither stagingListBody nor StagingBody found!');
                console.log('Available table bodies:', $('tbody').map(function() { return this.id; }).get());
            }
        } else {
            $('#stagingListBody').append(FinalMarkup);
        }
        console.log('Rows in table after append:', $('#stagingListBody').find('tr').length + ' in stagingListBody, ' + $('#StagingBody').find('tr').length + ' in StagingBody');
    }

    $scope.FinalDeployToProduction = function () {

        $('#wordpresshomeloading').show();

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        var data = {
            WPid: $('#WPid').html(),
            StagingID: DeploytoProductionID
        }

        var url = "/websites/DeploytoProduction";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Deploy To Production start!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response,
                type: 'error'
            });

        }

    };


    $scope.CreateBackup = function () {
        $('#wordpresshomeloading').show();
        $('#createbackupbutton').prop('disabled', true).html('<i class="fas fa-spinner fa-pulse"></i> Creating Backup...');

        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting creation Backups..";
        var data = {
            WPid: $('#WPid').html(),
            Backuptype: $('#backuptype').val()
        }
        var url = "/websites/WPCreateBackup";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Creating Backups!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {
                $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            alert(response)

        }

    };


    $scope.installwpcore = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/installwpcore";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched..',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }

    };

    $scope.dataintegrity = function () {

        $('#wordpresshomeloading').show();
        $('#wordpresshomeloadingsec').show();
        var data = {
            WPid: $('#WPid').html(),
        }

        $scope.wordpresshomeloading = false;

        var url = "/websites/dataintegrity";

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Results fetched',
                    type: 'success'
                });
                $('#SecurityResult').html(response.data.result);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#wordpresshomeloadingsec').hide();
            $scope.wordpresshomeloading = true;
            alert(response)

        }
    };

    $scope.updateSetting = function(site, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: site.id,
            setting: setting,
            value: site[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && site[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    site.PPUsername = "";
                    site.PPPassword = "";
                    $scope.currentWP = site;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            site[settingMap[setting]] = site[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.submitPasswordProtection = function() {
        console.log('submitPasswordProtection called');
        console.log('Current WP:', $scope.currentWP);
        
        if (!$scope.currentWP) {
            console.error('No WordPress site selected');
            new PNotify({
                title: 'Error!',
                text: 'No WordPress site selected.',
                type: 'error'
            });
            return;
        }

        if (!$scope.currentWP.PPUsername || !$scope.currentWP.PPPassword) {
            console.error('Missing username or password');
            new PNotify({
                title: 'Error!',
                text: 'Please provide both username and password',
                type: 'error'
            });
            return;
        }

        var data = {
            siteId: $scope.currentWP.id,
            setting: 'password-protection',
            value: 1,
            username: $scope.currentWP.PPUsername,
            password: $scope.currentWP.PPPassword
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log('Sending request with data:', data);
        $('#passwordProtectionModal').modal('hide');

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            console.log('Received response:', response);
            if (response.data.status) {
                new PNotify({
                    title: 'Success!',
                    text: 'Password protection enabled successfully!',
                    type: 'success'
                });
            } else {
                $scope.currentWP.passwordProtection = false;
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message || 'Failed to enable password protection',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            console.error('Request failed:', error);
            $scope.currentWP.passwordProtection = false;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server',
                type: 'error'
            });
        });
    };

});


var PluginsList = [];


function AddPluginToArray(cBox, name) {
    if (cBox.checked) {
        PluginsList.push(name);
        // alert(PluginsList);
    } else {
        const index = PluginsList.indexOf(name);
        if (index > -1) {
            PluginsList.splice(index, 1);
        }
        // alert(PluginsList);
    }
}

var ThemesList = [];

function AddThemeToArray(cBox, name) {
    if (cBox.checked) {
        ThemesList.push(name);
        // alert(ThemesList);
    } else {
        const index = ThemesList.indexOf(name);
        if (index > -1) {
            ThemesList.splice(index, 1);
        }
        // alert(ThemesList);
    }
}


function AppendToTable(table, markup) {
    $(table).append(markup);
}


//..................Restore Backup Home


app.controller('RestoreWPBackup', function ($scope, $http, $timeout, $window) {
    $scope.wordpresshomeloading = true;
    $scope.stagingDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;


    $scope.checkmethode = function () {
        var val = $('#RestoreMethode').children("option:selected").val();
        if (val == 1) {
            $('#Newsitediv').show();
            $('#exinstingsitediv').hide();
        } else if (val == 0) {
            $('#exinstingsitediv').show();
            $('#Newsitediv').hide();
        } else {

        }
    };


    $scope.RestoreWPbackupNow = function () {
        $('#wordpresshomeloading').show();
        $scope.wordpresshomeloading = false;
        $scope.stagingDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Start Restoring WordPress..";

        var Domain = $('#wprestoresubdirdomain').val()
        var path = $('#wprestoresubdirpath').val();
        var home = "1";

        if (typeof path != 'undefined' || path != '') {
            home = "0";
        }
        if (typeof path == 'undefined') {
            path = "";
        }


        var backuptype = $('#backuptype').html();
        var data;
        if (backuptype == "DataBase Backup") {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: '',
                path: path,
                home: home,
            }
        } else {
            data = {
                backupid: $('#backupid').html(),
                DesSite: $('#DesSite').children("option:selected").val(),
                Domain: Domain,
                path: path,
                home: home,
            }

        }

        var url = "/websites/RestoreWPbackupNow";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        // console.log(data)

        var d = $('#DesSite').children("option:selected").val();
        var c = $("input[name=Newdomain]").val();
        // if (d == -1 || c == "") {
        //     alert("Please Select Method of Backup Restore");
        // } else {
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        // }


        function ListInitialDatas(response) {
            wordpresshomeloading = true;
            $('#wordpresshomeloading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Restoring process starts!.',
                    type: 'success'
                });
                statusFile = response.data.tempStatusPath;
                getCreationStatus();

            } else {
                $('#wordpresshomeloading').hide();
                $scope.wordpresshomeloading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();

            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    }

    function getCreationStatus() {
        $('#wordpresshomeloading').show();

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            if (response.data.abort === 1) {
                $('#wordpresshomeloading').hide();

                if (response.data.installStatus === 1) {
                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $("#installProgressbackup").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    
                    // Re-enable buttons
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // For backup operations, refresh the backup list
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Backup created successfully!</span>');
                        if (typeof window.fetchBackupList === 'function') {
                            window.fetchBackupList();
                        }
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#backupStatus').text('');
                        }, 5000);
                    }
                    // For staging operations, refresh the staging list
                    else {
                        $('#stagingStatus').html('<span style="color: #10b981;"><i class="fas fa-check-circle"></i> Staging site created successfully!</span>');
                        $scope.fetchstaging();
                        // Clear status after 5 seconds
                        setTimeout(function() {
                            $('#stagingStatus').text('');
                        }, 5000);
                    }


                } else {
                    $('#wordpresshomeloading').hide();

                    $scope.wordpresshomeloading = true;
                    $scope.stagingDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $("#installProgressbackup").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;
                    
                    // Re-enable buttons on error
                    $('#createbackupbutton').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
                    $('button[ng-click="CreateStagingNow()"]').prop('disabled', false).html('<i class="fas fa-clone"></i> Create Staging Site');
                    
                    // Show error status
                    if (statusFile && statusFile.includes('backup')) {
                        $('#backupStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    } else {
                        $('#stagingStatus').html('<span style="color: #ef4444;"><i class="fas fa-times-circle"></i> ' + response.data.error_message + '</span>');
                    }


                }

            } else {

                $("#installProgress").css("width", response.data.installationProgress + "%");
                $("#installProgressbackup").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                
                // Update status displays with progress
                var statusHtml = '<i class="fas fa-spinner fa-pulse"></i> ' + response.data.currentStatus;
                if (response.data.installationProgress) {
                    statusHtml += ' (' + response.data.installationProgress + '%)';
                }
                
                if (statusFile && statusFile.includes('backup')) {
                    $('#backupStatus').html(statusHtml);
                } else {
                    $('#stagingStatus').html(statusHtml);
                }
                
                $timeout(getCreationStatus, 1000);

            }

        }

        function cantLoadInitialDatas(response) {
            $('#wordpresshomeloading').hide();
            $('#createBackupBtn').prop('disabled', false).html('<i class="fas fa-download"></i> Create Backup');
            $scope.wordpresshomeloading = true;
            $scope.stagingDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

    $scope.goBack = function () {
        $('#wordpresshomeloading').hide();
        $scope.wordpresshomeloading = true;
        $scope.stagingDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };
});


//.......................................Remote Backup

//........... delete DeleteBackupConfigNow

function DeleteBackupConfigNow(url) {
    window.location.href = url;
}

function DeleteRemoteBackupsiteNow(url) {
    window.location.href = url;
}

function DeleteBackupfileConfigNow(url) {
    window.location.href = url;
}


app.controller('RemoteBackupConfig', function ($scope, $http, $timeout, $window) {
    $scope.RemoteBackupLoading = true;
    $scope.SFTPBackUpdiv = true;

    $scope.EndpointURLdiv = true;
    $scope.Selectprovider = true;
    $scope.S3keyNamediv = true;
    $scope.Accesskeydiv = true;
    $scope.SecretKeydiv = true;
    $scope.SelectRemoteBackuptype = function () {
        var val = $scope.RemoteBackuptype;
        if (val == "SFTP") {
            $scope.SFTPBackUpdiv = false;
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        } else if (val == "S3") {
            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = false;
            $scope.S3keyNamediv = false;
            $scope.Accesskeydiv = false;
            $scope.SecretKeydiv = false;
            $scope.SFTPBackUpdiv = true;
        } else {
            $scope.RemoteBackupLoading = true;
            $scope.SFTPBackUpdiv = true;

            $scope.EndpointURLdiv = true;
            $scope.Selectprovider = true;
            $scope.S3keyNamediv = true;
            $scope.Accesskeydiv = true;
            $scope.SecretKeydiv = true;
        }
    }

    $scope.SelectProvidertype = function () {
        $scope.EndpointURLdiv = true;
        var provider = $scope.Providervalue
        if (provider == 'Backblaze') {
            $scope.EndpointURLdiv = false;
        } else {
            $scope.EndpointURLdiv = true;
        }
    }

    $scope.SaveBackupConfig = function () {
        $scope.RemoteBackupLoading = false;
        var Hname = $scope.Hostname;
        var Uname = $scope.Username;
        var Passwd = $scope.Password;
        var path = $scope.path;
        var type = $scope.RemoteBackuptype;
        var Providervalue = $scope.Providervalue;
        var data;
        if (type == "SFTP") {

            data = {
                Hname: Hname,
                Uname: Uname,
                Passwd: Passwd,
                path: path,
                type: type
            }
        } else if (type == "S3") {
            if (Providervalue == "Backblaze") {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    EndUrl: $scope.EndpointURL,
                    type: type
                }
            } else {
                data = {
                    S3keyname: $scope.S3keyName,
                    Provider: Providervalue,
                    AccessKey: $scope.Accesskey,
                    SecertKey: $scope.SecretKey,
                    type: type
                }

            }

        }
        var url = "/websites/SaveBackupConfig";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    }

});

var UpdatescheduleID;
app.controller('BackupSchedule', function ($scope, $http, $timeout, $window) {
    $scope.BackupScheduleLoading = true;
    $scope.SaveBackupSchedule = function () {
        $scope.RemoteBackupLoading = false;
        var FileRetention = $scope.Fretention;
        var Backfrequency = $scope.Bfrequency;


        var data = {
            FileRetention: FileRetention,
            Backfrequency: Backfrequency,
            ScheduleName: $scope.ScheduleName,
            RemoteConfigID: $('#RemoteConfigID').html(),
            BackupType: $scope.BackupType
        }
        var url = "/websites/SaveBackupSchedule";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };


    $scope.getupdateid = function (ID) {
        UpdatescheduleID = ID;
    }

    $scope.UpdateRemoteschedules = function () {
        $scope.RemoteBackupLoading = false;
        var Frequency = $scope.RemoteFrequency;
        var fretention = $scope.RemoteFileretention;

        var data = {
            ScheduleID: UpdatescheduleID,
            Frequency: Frequency,
            FileRetention: fretention
        }
        var url = "/websites/UpdateRemoteschedules";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Updated!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }
    };

    $scope.AddWPsiteforRemoteBackup = function () {
        $scope.RemoteBackupLoading = false;


        var data = {
            WpsiteID: $('#Wpsite').val(),
            RemoteScheduleID: $('#RemoteScheduleID').html()
        }
        var url = "/websites/AddWPsiteforRemoteBackup";


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };
        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();


            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.RemoteBackupLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };
});
/* Java script code to create account */

var website_create_domain_check = 0;

function website_create_checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        website_create_domain_check = 0;
        document.getElementById('Website_Create_Test_Domain').style.display = "block";
        document.getElementById('Website_Create_Own_Domain').style.display = "none";

    } else {
        document.getElementById('Website_Create_Test_Domain').style.display = "none";
        document.getElementById('Website_Create_Own_Domain').style.display = "block";
        website_create_domain_check = 1;
    }

    // alert(domain_check);
}


/* Java script code to create account ends here */

/* Java script code to list accounts */

$("#listFail").hide();


app.controller('listWebsites', function ($scope, $http, $window) {
    $scope.web = {};
    $scope.WebSitesList = [];
    $scope.loading = true; // Add loading state
    $scope.expandedSites = {}; // Track which sites are expanded

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    // Function to toggle site expansion
    $scope.toggleSite = function(site) {
        if (!$scope.expandedSites[site.domain]) {
            $scope.expandedSites[site.domain] = true;
            site.loading = true;
            // You can add any data fetching logic here if needed
            setTimeout(function() {
                site.loading = false;
                $scope.$apply();
            }, 500);
        } else {
            $scope.expandedSites[site.domain] = false;
        }
    };

    // Function to check if site is expanded
    $scope.isExpanded = function(siteId) {
        return $scope.expandedSites[siteId];
    };

    // Function to check if site data is loaded
    $scope.isDataLoaded = function(site) {
        return site.version !== undefined;
    };

    // Initial fetch of websites
    $scope.getFurtherWebsitesFromDB = function () {
        $scope.loading = true; // Set loading to true when starting fetch
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };

        var dataurl = "/websites/fetchWebsitesList";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $("#listFail").hide();
                // Expand the first site by default
                if ($scope.WebSitesList.length > 0) {
                    $scope.expandedSites[$scope.WebSitesList[0].domain] = true;
                }
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            $("#listFail").fadeIn();
            $scope.errorMessage = error.message || 'An error occurred while fetching websites';
            $scope.loading = false; // Set loading to false on error
        });
    };

    // Call it immediately
    $scope.getFurtherWebsitesFromDB();

    $scope.showWPSites = function(domain) {
        console.log('showWPSites called for domain:', domain);
        
        // Make sure domain is defined
        if (!domain) {
            console.error('Domain is undefined');
            return;
        }

        // Find the website in the list
        var site = $scope.WebSitesList.find(function(website) {
            return website.domain === domain;
        });

        if (!site) {
            console.error('Website not found:', domain);
            return;
        }

        // Set loading state
        site.loadingWPSites = true;

        // Toggle visibility
        site.showWPSites = !site.showWPSites;
        
        // If we're hiding, just return
        if (!site.showWPSites) {
            site.loadingWPSites = false;
            return;
        }

        var config = {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = $.param({
            domain: domain
        });

        $http.post('/websites/fetchWPDetails', data, config)
            .then(function(response) {
                console.log('Response received:', response);
                if (response.data.status === 1 && response.data.fetchStatus === 1) {
                    site.wp_sites = response.data.sites || [];
                    // Initialize loading states for each WP site
                    site.wp_sites.forEach(function(wp) {
                        wp.loading = false;
                        wp.loadingPlugins = false;
                        wp.loadingTheme = false;
                    });
                    $("#listFail").hide();
                } else {
                    $("#listFail").fadeIn();
                    site.showWPSites = false;
                    $scope.errorMessage = response.data.error_message || 'Failed to fetch WordPress sites';
                    console.error('Error in response:', response.data.error_message);
                    new PNotify({
                        title: 'Error!',
                        text: response.data.error_message || 'Failed to fetch WordPress sites',
                        type: 'error'
                    });
                }
            })
            .catch(function(error) {
                console.error('Request failed:', error);
                site.showWPSites = false;
                $("#listFail").fadeIn();
                $scope.errorMessage = error.message || 'An error occurred while fetching WordPress sites';
                new PNotify({
                    title: 'Error!',
                    text: error.message || 'Could not connect to server',
                    type: 'error'
                });
            })
            .finally(function() {
                site.loadingWPSites = false;
            });
    };

    $scope.visitSite = function(wp) {
        var url = wp.url || wp.domain;
        if (!url) return;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        window.open(url, '_blank');
    };

    $scope.wpLogin = function(wpId) {
        window.open('/websites/wpLogin?wpID=' + wpId, '_blank');
    };

    $scope.manageWP = function(wpId) {
        window.location.href = '/websites/WPHome?ID=' + wpId;
    };

    $scope.updateSetting = function(wp, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: wp.id,
            setting: setting,
            value: wp[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && wp[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    wp.PPUsername = "";
                    wp.PPPassword = "";
                    $scope.currentWP = wp;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.cyberPanelLoading = true;

    $scope.issueSSL = function (virtualHost) {
        $scope.cyberPanelLoading = false;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: virtualHost
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.SSL === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'SSL successfully issued.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        }


    };

    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {
        $scope.loading = true; // Set loading to true when starting search

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchWebsites";

        $http.post(dataurl, data, config).then(function(response) {
            if (response.data.listWebSiteStatus === 1) {
                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
            $scope.loading = false; // Set loading to false when done
        }).catch(function(error) {
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
            $scope.loading = false; // Set loading to false on error
        });
    };

    $scope.ScanWordpressSite = function () {

        $('#cyberPanelLoading').show();


        var url = "/websites/ScanWordpressSite";

        var data = {}


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            $('#cyberPanelLoading').hide();

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Successfully Saved!.',
                    type: 'success'
                });
                location.reload();

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }

        }

        function cantLoadInitialDatas(response) {
            $('#cyberPanelLoading').hide();
            new PNotify({
                title: 'Operation Failed!',
                text: response.data.error_message,
                type: 'error'
            });


        }


    };

    $scope.deleteWPSite = function(wp) {
        if (confirm('Are you sure you want to delete this WordPress site? This action cannot be undone.')) {
            window.location.href = '/websites/ListWPSites?DeleteID=' + wp.id;
        }
    };

    $scope.togglePasswordProtection = function(wp) {
        console.log('togglePasswordProtection called for:', wp);
        console.log('Current password protection state:', wp.passwordProtection);
        
        if (wp.passwordProtection) {
            // Show modal for credentials
            console.log('Showing modal for credentials');
            wp.PPUsername = "";
            wp.PPPassword = "";
            $scope.currentWP = wp;
            console.log('Current WP set to:', $scope.currentWP);
            $('#passwordProtectionModal').modal('show');
        } else {
            // Disable password protection
            console.log('Disabling password protection');
            var data = {
                siteId: wp.id,
                setting: 'password-protection',
                value: 0
            };
            
            var config = {
                headers: {
                    'X-CSRFToken': getCookie('csrftoken')
                }
            };

            console.log('Sending request with data:', data);
            $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
                console.log('Received response:', response);
                if (!response.data.status) {
                    wp.passwordProtection = !wp.passwordProtection;
                    new PNotify({
                        title: 'Operation Failed!',
                        text: response.data.error_message || 'Failed to disable password protection',
                        type: 'error'
                    });
                } else {
                    new PNotify({
                        title: 'Success!',
                        text: 'Password protection disabled successfully.',
                        type: 'success'
                    });
                }
            }).catch(function(error) {
                console.error('Request failed:', error);
                wp.passwordProtection = !wp.passwordProtection;
                new PNotify({
                    title: 'Operation Failed!',
                    text: 'Could not connect to server.',
                    type: 'error'
                });
            });
        }
    };

    $scope.submitPasswordProtection = function() {
        console.log('submitPasswordProtection called');
        console.log('Current WP:', $scope.currentWP);
        
        if (!$scope.currentWP) {
            console.error('No WordPress site selected');
            new PNotify({
                title: 'Error!',
                text: 'No WordPress site selected.',
                type: 'error'
            });
            return;
        }

        if (!$scope.currentWP.PPUsername || !$scope.currentWP.PPPassword) {
            console.error('Missing username or password');
            new PNotify({
                title: 'Error!',
                text: 'Please provide both username and password',
                type: 'error'
            });
            return;
        }

        var data = {
            siteId: $scope.currentWP.id,
            setting: 'password-protection',
            value: 1,
            username: $scope.currentWP.PPUsername,
            password: $scope.currentWP.PPPassword
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        console.log('Sending request with data:', data);
        $('#passwordProtectionModal').modal('hide');

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            console.log('Received response:', response);
            if (response.data.status) {
                new PNotify({
                    title: 'Success!',
                    text: 'Password protection enabled successfully!',
                    type: 'success'
                });
            } else {
                $scope.currentWP.passwordProtection = false;
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message || 'Failed to enable password protection',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            console.error('Request failed:', error);
            $scope.currentWP.passwordProtection = false;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server',
                type: 'error'
            });
        });
    };

    $scope.goToManage = function($event, domain) {
        $event.stopPropagation();
        window.location = '/websites/' + domain;
    };

    $scope.goToFileManager = function($event, domain) {
        $event.stopPropagation();
        window.location = '/filemanager/' + domain;
    };

});

app.controller('listChildDomainsMain', function ($scope, $http, $timeout) {

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    $scope.getFurtherWebsitesFromDB = function () {

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };


        dataurl = "/websites/fetchChildDomainsMain";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            if (response.data.listWebSiteStatus === 1) {

                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $scope.clients = JSON.parse(response.data.data);
                $("#listFail").hide();
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;

            }
        }

        function cantLoadInitialData(response) {
        }


    };
    $scope.getFurtherWebsitesFromDB();

    $scope.cyberPanelLoading = true;

    $scope.issueSSL = function (virtualHost) {
        $scope.cyberPanelLoading = false;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: virtualHost
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.SSL === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'SSL successfully issued.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });
        }


    };

    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {

        $scope.cyberPanelLoading = false;

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchChilds";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.listWebSiteStatus === 1) {

                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
        }

        function cantLoadInitialData(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
        }


    };

    $scope.initConvert = function (virtualHost) {
        $scope.domainName = virtualHost;
    };

    var statusFile;

    $scope.installationProgress = true;

    $scope.convert = function () {

        $scope.cyberPanelLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation..";

        var ssl, dkimCheck, openBasedir;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        if ($scope.dkimCheck === true) {
            dkimCheck = 1;
        } else {
            dkimCheck = 0
        }

        if ($scope.openBasedir === true) {
            openBasedir = 1;
        } else {
            openBasedir = 0
        }

        url = "/websites/convertDomainToSite";


        var data = {
            package: $scope.packageForWebsite,
            domainName: $scope.domainName,
            adminEmail: $scope.adminEmail,
            phpSelection: $scope.phpSelection,
            websiteOwner: $scope.websiteOwner,
            ssl: ssl,
            dkimCheck: dkimCheck,
            openBasedir: openBasedir
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createWebSiteStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.cyberPanelLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.goBackDisable = false;

                $scope.currentStatus = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.cyberPanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }


    };
    $scope.goBack = function () {
        $scope.cyberPanelLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.cyberPanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.cyberPanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $scope.currentStatus = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.cyberPanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }


    }

    var DeleteDomain;
    $scope.deleteDomainInit = function (childDomainForDeletion) {
        DeleteDomain = childDomainForDeletion;
    };

    $scope.deleteChildDomain = function () {
        $scope.cyberPanelLoading = false;
        url = "/websites/submitDomainDeletion";

        var data = {
            websiteName: DeleteDomain,
            DeleteDocRoot: $scope.DeleteDocRoot
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.websiteDeleteStatus === 1) {
                new PNotify({
                    title: 'Success!',
                    text: 'Child Domain successfully deleted.',
                    type: 'success'
                });
                $scope.getFurtherWebsitesFromDB();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page',
                type: 'error'
            });

        }

    };

});

/* Java script code to list accounts ends here */


/* Java script code to delete Website */


$("#websiteDeleteFailure").hide();
$("#websiteDeleteSuccess").hide();

$("#deleteWebsiteButton").hide();
$("#deleteLoading").hide();

app.controller('deleteWebsiteControl', function ($scope, $http) {


    $scope.deleteWebsite = function () {

        $("#deleteWebsiteButton").fadeIn();


    };

    $scope.deleteWebsiteFinal = function () {

        $("#deleteLoading").show();

        var websiteName = $scope.websiteToBeDeleted;


        url = "/websites/submitWebsiteDeletion";

        var data = {
            websiteName: websiteName
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.websiteDeleteStatus === 0) {
                $scope.errorMessage = response.data.error_message;
                $("#websiteDeleteFailure").fadeIn();
                $("#websiteDeleteSuccess").hide();
                $("#deleteWebsiteButton").hide();


                $("#deleteLoading").hide();

            } else {
                $("#websiteDeleteFailure").hide();
                $("#websiteDeleteSuccess").fadeIn();
                $("#deleteWebsiteButton").hide();
                $scope.deletedWebsite = websiteName;
                $("#deleteLoading").hide();

            }


        }

        function cantLoadInitialDatas(response) {
        }


    };

});


/* Java script code to delete website ends here */


/* Java script code to modify package ends here */

$("#canNotModify").hide();
$("#webSiteDetailsToBeModified").hide();
$("#websiteModifyFailure").hide();
$("#websiteModifySuccess").hide();
$("#websiteSuccessfullyModified").hide();
$("#modifyWebsiteLoading").hide();
$("#modifyWebsiteButton").hide();

app.controller('modifyWebsitesController', function ($scope, $http) {

    $scope.fetchWebsites = function () {

        $("#modifyWebsiteLoading").show();


        var websiteToBeModified = $scope.websiteToBeModified;

        url = "/websites/getWebsiteDetails";

        var data = {
            websiteToBeModified: websiteToBeModified,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.modifyStatus === 0) {
                console.log(response.data);
                $scope.errorMessage = response.data.error_message;
                $("#websiteModifyFailure").fadeIn();
                $("#websiteModifySuccess").hide();
                $("#modifyWebsiteButton").hide();
                $("#modifyWebsiteLoading").hide();
                $("#canNotModify").hide();


            } else {
                console.log(response.data);
                $("#modifyWebsiteButton").fadeIn();

                $scope.adminEmail = response.data.adminEmail;
                $scope.currentPack = response.data.current_pack;
                $scope.webpacks = JSON.parse(response.data.packages);
                $scope.adminNames = JSON.parse(response.data.adminNames);
                $scope.currentAdmin = response.data.currentAdmin;

                $("#webSiteDetailsToBeModified").fadeIn();
                $("#websiteModifySuccess").fadeIn();
                $("#modifyWebsiteButton").fadeIn();
                $("#modifyWebsiteLoading").hide();
                $("#canNotModify").hide();


            }


        }

        function cantLoadInitialDatas(response) {
            $("#websiteModifyFailure").fadeIn();
        }

    };


    $scope.modifyWebsiteFunc = function () {

        var domain = $scope.websiteToBeModified;
        var packForWeb = $scope.selectedPack;
        var email = $scope.adminEmail;
        var phpVersion = $scope.phpSelection;
        var admin = $scope.selectedAdmin;


        $("#websiteModifyFailure").hide();
        $("#websiteModifySuccess").hide();
        $("#websiteSuccessfullyModified").hide();
        $("#canNotModify").hide();
        $("#modifyWebsiteLoading").fadeIn();


        url = "/websites/saveWebsiteChanges";

        var data = {
            domain: domain,
            packForWeb: packForWeb,
            email: email,
            phpVersion: phpVersion,
            admin: admin
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.saveStatus === 0) {
                $scope.errMessage = response.data.error_message;

                $("#canNotModify").fadeIn();
                $("#websiteModifyFailure").hide();
                $("#websiteModifySuccess").hide();
                $("#websiteSuccessfullyModified").hide();
                $("#modifyWebsiteLoading").hide();


            } else {
                $("#modifyWebsiteButton").hide();
                $("#canNotModify").hide();
                $("#websiteModifyFailure").hide();
                $("#websiteModifySuccess").hide();

                $("#websiteSuccessfullyModified").fadeIn();
                $("#modifyWebsiteLoading").hide();

                $scope.websiteModified = domain;


            }


        }

        function cantLoadInitialDatas(response) {
            $scope.errMessage = response.data.error_message;
            $("#canNotModify").fadeIn();
        }


    };

});

/* Java script code to Modify Pacakge ends here */


/* Java script code to create account */
var website_child_domain_check = 0;

function website_child_domain_checkbox_function() {

    var checkBox = document.getElementById("myCheck");
    // Get the output text


    // If the checkbox is checked, display the output text
    if (checkBox.checked == true) {
        website_child_domain_check = 0;
        document.getElementById('Website_Create_Test_Domain').style.display = "block";
        document.getElementById('Website_Create_Own_Domain').style.display = "none";

    } else {
        document.getElementById('Website_Create_Test_Domain').style.display = "none";
        document.getElementById('Website_Create_Own_Domain').style.display = "block";
        website_child_domain_check = 1;
    }

    // alert(domain_check);
}

app.controller('websitePages', function ($scope, $http, $timeout, $window) {

    $scope.openWebTerminal = function() {
        console.log('[DEBUG] openWebTerminal called');
        $('#web-terminal-modal').modal('show');
        console.log('[DEBUG] Modal should now be visible');

        if ($scope.term) {
            console.log('[DEBUG] Disposing previous terminal instance');
            $scope.term.dispose();
        }
        var term = new Terminal({
            cursorBlink: true,
            fontFamily: 'monospace',
            fontSize: 14,
            theme: { background: '#000' }
        });
        $scope.term = term;
        term.open(document.getElementById('xterm-container'));
        term.focus();
        console.log('[DEBUG] Terminal initialized and opened');

        // Fetch JWT from backend with CSRF token
        var domain = $("#domainNamePage").text();
        var csrftoken = getCookie('csrftoken');
        console.log('[DEBUG] Fetching JWT for domain:', domain);
        $http.post('/websites/getTerminalJWT', { domain: domain }, {
            headers: { 'X-CSRFToken': csrftoken }
        })
        .then(function(response) {
            console.log('[DEBUG] JWT fetch response:', response);
            if (response.data.status === 1 && response.data.token) {
                var token = response.data.token;
                var ssh_user = response.data.ssh_user;
                var wsProto = location.protocol === 'https:' ? 'wss' : 'ws';
                var wsUrl = wsProto + '://' + window.location.hostname + ':8888/ws?token=' + encodeURIComponent(token) + '&ssh_user=' + encodeURIComponent(ssh_user);
                console.log('[DEBUG] Connecting to WebSocket:', wsUrl);
                var socket = new WebSocket(wsUrl);
                socket.binaryType = 'arraybuffer';
                $scope.terminalSocket = socket;

                socket.onopen = function() {
                    console.log('[DEBUG] WebSocket connection opened');
                    term.write('\x1b[32mConnected.\x1b[0m\r\n');
                };
                socket.onclose = function(event) {
                    console.log('[DEBUG] WebSocket connection closed', event);
                    term.write('\r\n\x1b[31mConnection closed.\x1b[0m\r\n');
                    // Optionally, log modal state
                    console.log('[DEBUG] Modal state on close:', $('#web-terminal-modal').is(':visible'));
                };
                socket.onerror = function(e) {
                    console.log('[DEBUG] WebSocket error', e);
                    term.write('\r\n\x1b[31mWebSocket error.\x1b[0m\r\n');
                };
                socket.onmessage = function(event) {
                    if (event.data instanceof ArrayBuffer) {
                        var text = new Uint8Array(event.data);
                        term.write(new TextDecoder().decode(text));
                    } else if (typeof event.data === 'string') {
                        term.write(event.data);
                    }
                };
                term.onData(function(data) {
                    if (socket.readyState === WebSocket.OPEN) {
                        var encoder = new TextEncoder();
                        socket.send(encoder.encode(data));
                    }
                });
                term.onResize(function(size) {
                    if (socket.readyState === WebSocket.OPEN) {
                        var msg = JSON.stringify({resize: {cols: size.cols, rows: size.rows}});
                        socket.send(msg);
                    }
                });
                $('#web-terminal-modal').on('hidden.bs.modal', function() {
                    console.log('[DEBUG] Modal hidden event triggered');
                    if ($scope.term) {
                        $scope.term.dispose();
                        $scope.term = null;
                    }
                    if ($scope.terminalSocket) {
                        $scope.terminalSocket.close();
                        $scope.terminalSocket = null;
                    }
                });
            } else {
                console.log('[DEBUG] Failed to get terminal token', response);
                term.write('\x1b[31mFailed to get terminal token.\x1b[0m\r\n');
            }
        }, function(error) {
            console.log('[DEBUG] Failed to contact backend', error);
            term.write('\x1b[31mFailed to contact backend.\x1b[0m\r\n');
        });
    };

    $scope.logFileLoading = true;
    $scope.logsFeteched = true;
    $scope.couldNotFetchLogs = true;
    $scope.couldNotConnect = true;
    $scope.fetchedData = true;
    $scope.hideLogs = true;
    $scope.hideErrorLogs = true;

    $scope.hidelogsbtn = function () {
        $scope.hideLogs = true;
    };

    $scope.hideErrorLogsbtn = function () {
        $scope.hideLogs = true;
    };

    $scope.fileManagerURL = "/filemanager/" + $("#domainNamePage").text();
    $scope.wordPressInstallURL = $("#domainNamePage").text() + "/wordpressInstall";
    $scope.joomlaInstallURL = $("#domainNamePage").text() + "/joomlaInstall";
    $scope.setupGit = $("#domainNamePage").text() + "/setupGit";
    $scope.installPrestaURL = $("#domainNamePage").text() + "/installPrestaShop";
    $scope.installMagentoURL = $("#domainNamePage").text() + "/installMagento";
    $scope.installMauticURL = $("#domainNamePage").text() + "/installMautic";
    $scope.domainAliasURL = "/websites/" + $("#domainNamePage").text() + "/domainAlias";
    $scope.previewUrl = "/preview/" + $("#domainNamePage").text() + "/";

    var logType = 0;
    $scope.pageNumber = 1;

    $scope.fetchLogs = function (type) {

        var pageNumber = $scope.pageNumber;


        if (type == 3) {
            pageNumber = $scope.pageNumber + 1;
            $scope.pageNumber = pageNumber;
        } else if (type == 4) {
            pageNumber = $scope.pageNumber - 1;
            $scope.pageNumber = pageNumber;
        } else {
            logType = type;
        }


        $scope.logFileLoading = false;
        $scope.logsFeteched = true;
        $scope.couldNotFetchLogs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedData = false;
        $scope.hideErrorLogs = true;


        url = "/websites/getDataFromLogFile";

        var domainNamePage = $("#domainNamePage").text();


        var data = {
            logType: logType,
            virtualHost: domainNamePage,
            page: pageNumber,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.logstatus == 1) {


                $scope.logFileLoading = true;
                $scope.logsFeteched = false;
                $scope.couldNotFetchLogs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedData = false;
                $scope.hideLogs = false;


                $scope.records = JSON.parse(response.data.data);

            } else {

                $scope.logFileLoading = true;
                $scope.logsFeteched = true;
                $scope.couldNotFetchLogs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = false;


                $scope.errorMessage = response.data.error_message;
                console.log(domainNamePage)

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.logFileLoading = true;
            $scope.logsFeteched = true;
            $scope.couldNotFetchLogs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedData = true;
            $scope.hideLogs = false;

        }


    };

    $scope.errorPageNumber = 1;


    $scope.fetchErrorLogs = function (type) {

        var errorPageNumber = $scope.errorPageNumber;


        if (type == 3) {
            errorPageNumber = $scope.errorPageNumber + 1;
            $scope.errorPageNumber = errorPageNumber;
        } else if (type == 4) {
            errorPageNumber = $scope.errorPageNumber - 1;
            $scope.errorPageNumber = errorPageNumber;
        } else {
            logType = type;
        }

        // notifications

        $scope.logFileLoading = false;
        $scope.logsFeteched = true;
        $scope.couldNotFetchLogs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedData = true;
        $scope.hideErrorLogs = true;
        $scope.hideLogs = false;


        url = "/websites/fetchErrorLogs";

        var domainNamePage = $("#domainNamePage").text();


        var data = {
            virtualHost: domainNamePage,
            page: errorPageNumber,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.logstatus === 1) {


                // notifications

                $scope.logFileLoading = true;
                $scope.logsFeteched = false;
                $scope.couldNotFetchLogs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = false;
                $scope.hideErrorLogs = false;


                $scope.errorLogsData = response.data.data;

            } else {

                // notifications

                $scope.logFileLoading = true;
                $scope.logsFeteched = true;
                $scope.couldNotFetchLogs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = true;
                $scope.hideErrorLogs = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            // notifications

            $scope.logFileLoading = true;
            $scope.logsFeteched = true;
            $scope.couldNotFetchLogs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedData = true;
            $scope.hideLogs = true;
            $scope.hideErrorLogs = true;

        }


    };

    ///////// Configurations Part

    $scope.configurationsBox = true;
    $scope.configsFetched = true;
    $scope.couldNotFetchConfigs = true;
    $scope.couldNotConnect = true;
    $scope.fetchedConfigsData = true;
    $scope.configFileLoading = true;
    $scope.configSaved = true;
    $scope.couldNotSaveConfigurations = true;

    $scope.hideconfigbtn = function () {

        $scope.configurationsBox = true;
    };

    $scope.fetchConfigurations = function () {


        $scope.hidsslconfigs = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = true;


        //Rewrite rules
        $scope.configurationsBoxRewrite = true;
        $scope.rewriteRulesFetched = true;
        $scope.couldNotFetchRewriteRules = true;
        $scope.rewriteRulesSaved = true;
        $scope.couldNotSaveRewriteRules = true;
        $scope.fetchedRewriteRules = true;
        $scope.saveRewriteRulesBTN = true;

        ///

        $scope.configFileLoading = false;


        url = "/websites/getDataFromConfigFile";

        var virtualHost = $("#domainNamePage").text();


        var data = {
            virtualHost: virtualHost,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.configstatus === 1) {

                //Rewrite rules

                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;

                ///

                $scope.configurationsBox = false;
                $scope.configsFetched = false;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = false;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = false;


                $scope.configData = response.data.configData;

            } else {

                //Rewrite rules
                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;

                ///
                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            //Rewrite rules
            $scope.configurationsBoxRewrite = true;
            $scope.rewriteRulesFetched = true;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = true;
            ///

            $scope.configurationsBox = false;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;


        }


    };

    $scope.saveCongiruations = function () {

        $scope.configFileLoading = false;


        url = "/websites/saveConfigsToFile";

        var virtualHost = $("#domainNamePage").text();
        var configData = $scope.configData;


        var data = {
            virtualHost: virtualHost,
            configData: configData,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.configstatus === 1) {

                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = false;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;


            } else {
                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = false;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = false;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configurationsBox = false;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;


        }


    };


    ///////// Rewrite Rules

    $scope.configurationsBoxRewrite = true;
    $scope.rewriteRulesFetched = true;
    $scope.couldNotFetchRewriteRules = true;
    $scope.rewriteRulesSaved = true;
    $scope.couldNotSaveRewriteRules = true;
    $scope.fetchedRewriteRules = true;
    $scope.saveRewriteRulesBTN = true;

    $scope.hideRewriteRulesbtn = function () {
        $scope.configurationsBoxRewrite = true;
    };

    $scope.fetchRewriteFules = function () {

        $scope.hidsslconfigs = true;
        $scope.configurationsBox = true;
        $scope.changePHPView = true;


        $scope.configurationsBox = true;
        $scope.configsFetched = true;
        $scope.couldNotFetchConfigs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedConfigsData = true;
        $scope.configFileLoading = true;
        $scope.configSaved = true;
        $scope.couldNotSaveConfigurations = true;
        $scope.saveConfigBtn = true;

        $scope.configFileLoading = false;


        url = "/websites/getRewriteRules";

        var virtualHost = $("#domainNamePage").text();


        var data = {
            virtualHost: virtualHost,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.rewriteStatus == 1) {


                // from main

                $scope.configurationsBox = true;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.fetchedConfigsData = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;

                // main ends

                $scope.configFileLoading = true;

                //


                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = false;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = false;
                $scope.saveRewriteRulesBTN = false;
                $scope.couldNotConnect = true;


                $scope.rewriteRules = response.data.rewriteRules;

            } else {
                // from main
                $scope.configurationsBox = true;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;
                // from main

                $scope.configFileLoading = true;

                ///

                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = false;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;
                $scope.couldNotConnect = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {
            // from main

            $scope.configurationsBox = true;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;
            $scope.saveConfigBtn = true;

            // from main

            $scope.configFileLoading = true;

            ///

            $scope.configurationsBoxRewrite = true;
            $scope.rewriteRulesFetched = true;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = true;

            $scope.couldNotConnect = false;


        }


    };

    $scope.saveRewriteRules = function () {

        $scope.configFileLoading = false;


        url = "/websites/saveRewriteRules";

        var virtualHost = $("#domainNamePage").text();
        var rewriteRules = $scope.rewriteRules;


        var data = {
            virtualHost: virtualHost,
            rewriteRules: rewriteRules,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.rewriteStatus == 1) {

                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = false;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;
                $scope.configFileLoading = true;


            } else {
                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = false;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = false;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = false;

                $scope.configFileLoading = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configurationsBoxRewrite = false;
            $scope.rewriteRulesFetched = false;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = false;

            $scope.configFileLoading = true;

            $scope.couldNotConnect = false;


        }


    };

    //////// Application Installation part

    $scope.installationDetailsForm = true;
    $scope.installationDetailsFormJoomla = true;
    $scope.applicationInstallerLoading = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;


    $scope.installationDetails = function () {

        $scope.installationDetailsForm = !$scope.installationDetailsForm;
        $scope.installationDetailsFormJoomla = true;

    };

    $scope.installationDetailsJoomla = function () {

        $scope.installationDetailsFormJoomla = !$scope.installationDetailsFormJoomla;
        $scope.installationDetailsForm = true;

    };

    $scope.installWordpress = function () {


        $scope.installationDetailsForm = false;
        $scope.applicationInstallerLoading = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;

        var domain = $("#domainNamePage").text();
        var path = $scope.installPath;

        url = "/websites/installWordpress";

        var home = "1";

        if (typeof path != 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            home: home,
            path: path,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                if (typeof path != 'undefined') {
                    $scope.installationURL = "http://" + domain + "/" + path;
                } else {
                    $scope.installationURL = domain;
                }

                $scope.installationDetailsForm = false;
                $scope.applicationInstallerLoading = true;
                $scope.installationFailed = true;
                $scope.installationSuccessfull = false;
                $scope.couldNotConnect = true;

            } else {

                $scope.installationDetailsForm = false;
                $scope.applicationInstallerLoading = true;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.installationDetailsForm = false;
            $scope.applicationInstallerLoading = true;
            $scope.installationFailed = true;
            $scope.installationSuccessfull = true;
            $scope.couldNotConnect = false;

        }

    };

    $scope.installJoomla = function () {


        $scope.installationDetailsFormJoomla = false;
        $scope.applicationInstallerLoading = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;

        var domain = $("#domainNamePage").text();
        var path = $scope.installPath;
        var username = 'admin';
        var password = $scope.password;
        var prefix = $scope.prefix;


        url = "/websites/installJoomla";

        var home = "1";

        if (typeof path != 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            siteName: $scope.siteName,
            home: home,
            path: path,
            password: password,
            prefix: prefix,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                if (typeof path != 'undefined') {
                    $scope.installationURL = "http://" + domain + "/" + path;
                } else {
                    $scope.installationURL = domain;
                }

                $scope.installationDetailsFormJoomla = false;
                $scope.applicationInstallerLoading = true;
                $scope.installationFailed = true;
                $scope.installationSuccessfull = false;
                $scope.couldNotConnect = true;

            } else {

                $scope.installationDetailsFormJoomla = false;
                $scope.applicationInstallerLoading = true;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.installationDetailsFormJoomla = false;
            $scope.applicationInstallerLoading = true;
            $scope.installationFailed = true;
            $scope.installationSuccessfull = true;
            $scope.couldNotConnect = false;

        }

    };


    //////// SSL Part

    $scope.sslSaved = true;
    $scope.couldNotSaveSSL = true;
    $scope.hidsslconfigs = true;
    $scope.couldNotConnect = true;


    $scope.hidesslbtn = function () {
        $scope.hidsslconfigs = true;
    };

    $scope.addSSL = function () {
        $scope.hidsslconfigs = false;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = true;
    };

    $scope.saveSSL = function () {


        $scope.configFileLoading = false;

        url = "/websites/saveSSL";

        var virtualHost = $("#domainNamePage").text();
        var cert = $scope.cert;
        var key = $scope.key;


        var data = {
            virtualHost: virtualHost,
            cert: cert,
            key: key
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.sslStatus === 1) {

                $scope.sslSaved = false;
                $scope.couldNotSaveSSL = true;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;


            } else {

                $scope.sslSaved = true;
                $scope.couldNotSaveSSL = false;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.sslSaved = true;
            $scope.couldNotSaveSSL = true;
            $scope.couldNotConnect = false;
            $scope.configFileLoading = true;


        }

    };

    //// Change PHP Master

    $scope.failedToChangePHPMaster = true;
    $scope.phpChangedMaster = true;
    $scope.couldNotConnect = true;

    $scope.changePHPView = true;


    $scope.hideChangePHPMaster = function () {
        $scope.changePHPView = true;
    };

    $scope.changePHPMaster = function () {
        $scope.hidsslconfigs = true;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = false;
    };

    $scope.changePHPVersionMaster = function (childDomain, phpSelection) {

        // notifcations

        $scope.configFileLoading = false;

        var url = "/websites/changePHP";

        var data = {
            childDomain: $("#domainNamePage").text(),
            phpSelection: $scope.phpSelectionMaster,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changePHP === 1) {

                $scope.configFileLoading = true;
                $scope.websiteDomain = $("#domainNamePage").text();


                // notifcations

                $scope.failedToChangePHPMaster = true;
                $scope.phpChangedMaster = false;
                $scope.couldNotConnect = true;


            } else {

                $scope.configFileLoading = true;
                $scope.errorMessage = response.data.error_message;

                // notifcations

                $scope.failedToChangePHPMaster = false;
                $scope.phpChangedMaster = true;
                $scope.couldNotConnect = true;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configFileLoading = true;

            // notifcations

            $scope.failedToChangePHPMaster = true;
            $scope.phpChangedMaster = true;
            $scope.couldNotConnect = false;

        }

    };

    ////// create domain part

    $("#domainCreationForm").hide();

    $scope.showCreateDomainForm = function () {
        $("#domainCreationForm").fadeIn();
    };

    $scope.hideDomainCreationForm = function () {
        $("#domainCreationForm").fadeOut();
    };

    $scope.masterDomain = $("#domainNamePage").text();

    // notifcations settings
    $scope.domainLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;
    $scope.DomainCreateForm = true;

    var statusFile;


    $scope.webselection = true;
    $scope.WebsiteType = function () {
        var type = $scope.websitetype;
        if (type == 'Sub Domain') {
            $scope.webselection = false;
            $scope.DomainCreateForm = true;

        } else if (type == 'Addon Domain') {
            $scope.DomainCreateForm = false;
            $scope.webselection = true;
            $scope.masterDomain = $('#defaultSite').html()
        }
    };

    $scope.WebsiteSelection = function () {
        $scope.DomainCreateForm = false;
    };

    $scope.createDomain = function () {

        $scope.domainLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting creation..";
        $scope.DomainCreateForm = true;

        var ssl, dkimCheck, openBasedir, apacheBackend;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        if ($scope.dkimCheck === true) {
            dkimCheck = 1;
        } else {
            dkimCheck = 0
        }

        if ($scope.openBasedir === true) {
            openBasedir = 1;
        } else {
            openBasedir = 0
        }


        if ($scope.apacheBackend === true) {
            apacheBackend = 1;
        } else {
            apacheBackend = 0
        }


        url = "/websites/submitDomainCreation";
        var domainName = $scope.domainNameCreate;
        var phpSelection = $scope.phpSelection;

        var path = $scope.docRootPath;

        if (typeof path === 'undefined') {
            path = "";
        }
        var package = $scope.packageForWebsite;

        // if (website_child_domain_check == 0) {
        //     var Part2_domainNameCreate = document.getElementById('Part2_domainNameCreate').value;
        //     var domainName = document.getElementById('TestDomainNameCreate').value + Part2_domainNameCreate;
        // }
        // if (website_child_domain_check == 1) {
        //
        //     var domainName = $scope.own_domainNameCreate;
        // }
        var type = $scope.websitetype;

        var domainName = $scope.domainNameCreate;


        var data = {
            domainName: domainName,
            phpSelection: phpSelection,
            ssl: ssl,
            path: path,
            masterDomain: $scope.masterDomain,
            dkimCheck: dkimCheck,
            openBasedir: openBasedir,
            apacheBackend: apacheBackend
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        // console.log(data)

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createWebSiteStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.domainLoading = true;
                $scope.installationDetailsForm = true;
                $scope.DomainCreateForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;
            $scope.installationDetailsForm = true;
            $scope.DomainCreateForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.goBack = function () {
        $scope.domainLoading = true;
        $scope.installationDetailsForm = false;
        $scope.DomainCreateForm = true;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.DomainCreateForm = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.domainLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.domainLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.DomainCreateForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;
            $scope.installationDetailsForm = true;
            $scope.DomainCreateForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }


    ////// List Domains Part

    ////////////////////////

    // notifcations

    $scope.phpChanged = true;
    $scope.domainError = true;
    $scope.couldNotConnect = true;
    $scope.domainDeleted = true;
    $scope.sslIssued = true;
    $scope.childBaseDirChanged = true;

    $("#listDomains").hide();


    $scope.showListDomains = function () {
        fetchDomains();
        $("#listDomains").fadeIn();
    };

    $scope.hideListDomains = function () {
        $("#listDomains").fadeOut();
    };

    function fetchDomains() {
        $scope.domainLoading = false;

        var url = "/websites/fetchDomains";

        var data = {
            masterDomain: $("#domainNamePage").text(),
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.fetchStatus === 1) {

                $scope.childDomains = JSON.parse(response.data.data);
                $scope.domainLoading = true;


            } else {
                $scope.domainError = false;
                $scope.errorMessage = response.data.error_message;
                $scope.domainLoading = true;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.couldNotConnect = false;

        }

    }

    $scope.changePHP = function (childDomain, phpSelection) {

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;
        $scope.domainLoading = false;
        $scope.childBaseDirChanged = true;

        var url = "/websites/changePHP";

        var data = {
            childDomain: childDomain,
            phpSelection: phpSelection,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changePHP === 1) {

                $scope.domainLoading = true;

                $scope.changedPHPVersion = phpSelection;


                // notifcations

                $scope.phpChanged = false;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.childBaseDirChanged = true;


            } else {
                $scope.errorMessage = response.data.error_message;
                $scope.domainLoading = true;

                // notifcations

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.childBaseDirChanged = true;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;

            // notifcations

            $scope.phpChanged = true;
            $scope.domainError = false;
            $scope.couldNotConnect = true;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;
            $scope.childBaseDirChanged = true;

        }

    };

    $scope.changeChildBaseDir = function (childDomain, openBasedirValue) {

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;
        $scope.domainLoading = false;
        $scope.childBaseDirChanged = true;


        var url = "/websites/changeOpenBasedir";

        var data = {
            domainName: childDomain,
            openBasedirValue: openBasedirValue
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changeOpenBasedir === 1) {

                $scope.phpChanged = true;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.domainLoading = true;
                $scope.childBaseDirChanged = false;

            } else {

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.domainLoading = true;
                $scope.childBaseDirChanged = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.phpChanged = true;
            $scope.domainError = true;
            $scope.couldNotConnect = false;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;
            $scope.domainLoading = true;
            $scope.childBaseDirChanged = true;


        }

    }

    $scope.deleteChildDomain = function (childDomain) {
        $scope.domainLoading = false;

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;

        url = "/websites/submitDomainDeletion";

        var data = {
            websiteName: childDomain,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.websiteDeleteStatus === 1) {

                $scope.domainLoading = true;
                $scope.deletedDomain = childDomain;

                fetchDomains();


                // notifications

                $scope.phpChanged = true;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = false;
                $scope.sslIssued = true;


            } else {
                $scope.errorMessage = response.data.error_message;
                $scope.domainLoading = true;

                // notifcations

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;

            // notifcations

            $scope.phpChanged = true;
            $scope.domainError = true;
            $scope.couldNotConnect = false;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;

        }

    };

    $scope.issueSSL = function (childDomain, path) {
        $scope.domainLoading = false;

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;
        $scope.childBaseDirChanged = true;

        var url = "/manageSSL/issueSSL";


        var data = {
            virtualHost: childDomain,
            path: path,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.SSL === 1) {

                $scope.domainLoading = true;

                // notifcations

                $scope.phpChanged = true;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = false;
                $scope.childBaseDirChanged = true;


                $scope.sslDomainIssued = childDomain;


            } else {
                $scope.domainLoading = true;

                $scope.errorMessage = response.data.error_message;

                // notifcations

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.childBaseDirChanged = true;

            }


        }

        function cantLoadInitialDatas(response) {

            // notifcations

            $scope.phpChanged = true;
            $scope.domainError = true;
            $scope.couldNotConnect = false;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;
            $scope.childBaseDirChanged = true;


        }


    };


    /// Open_basedir protection

    $scope.baseDirLoading = true;
    $scope.operationFailed = true;
    $scope.operationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.openBaseDirBox = true;


    $scope.openBaseDirView = function () {
        $scope.openBaseDirBox = false;
    };

    $scope.hideOpenBasedir = function () {
        $scope.openBaseDirBox = true;
    };

    $scope.applyOpenBasedirChanges = function (childDomain, phpSelection) {

        // notifcations

        $scope.baseDirLoading = false;
        $scope.operationFailed = true;
        $scope.operationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.openBaseDirBox = false;


        var url = "/websites/changeOpenBasedir";

        var data = {
            domainName: $("#domainNamePage").text(),
            openBasedirValue: $scope.openBasedirValue
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changeOpenBasedir === 1) {

                $scope.baseDirLoading = true;
                $scope.operationFailed = true;
                $scope.operationSuccessfull = false;
                $scope.couldNotConnect = true;
                $scope.openBaseDirBox = false;

            } else {

                $scope.baseDirLoading = true;
                $scope.operationFailed = false;
                $scope.operationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.openBaseDirChanged = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.baseDirLoading = true;
            $scope.operationFailed = true;
            $scope.operationSuccessfull = true;
            $scope.couldNotConnect = false;
            $scope.openBaseDirBox = false;


        }

    }


    // REWRITE Template

    const httpToHTTPS = `### Rewrite Rules Added by CyberPanel Rewrite Rule Generator

RewriteEngine On
RewriteCond %{HTTPS}  !=on
RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]

### End CyberPanel Generated Rules.

`;

    const WWWToNonWWW = `### Rewrite Rules Added by CyberPanel Rewrite Rule Generator

RewriteEngine On
RewriteCond %{HTTP_HOST} ^www\.(.*)$
RewriteRule ^(.*)$ http://%1/$1 [L,R=301]

### End CyberPanel Generated Rules.

`;

    const nonWWWToWWW = `### Rewrite Rules Added by CyberPanel Rewrite Rule Generator

RewriteEngine On
RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteRule ^(.*)$ http://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

### End CyberPanel Generated Rules.

`;

    const WordpressProtect = `### Rewrite Rules Added by CyberPanel Rewrite Rule Generator

RewriteEngine On
RewriteRule ^/(xmlrpc|wp-trackback)\.php - [F,L,NC]

### End CyberPanel Generated Rules.

`;

    $scope.applyRewriteTemplate = function () {

        if ($scope.rewriteTemplate === "Force HTTP -> HTTPS") {
            $scope.rewriteRules = httpToHTTPS + $scope.rewriteRules;
        } else if ($scope.rewriteTemplate === "Force NON-WWW -> WWW") {
            $scope.rewriteRules = nonWWWToWWW + $scope.rewriteRules;
        } else if ($scope.rewriteTemplate === "Force WWW -> NON-WWW") {
            $scope.rewriteRules = WWWToNonWWW + $scope.rewriteRules;
        } else if ($scope.rewriteTemplate === "Disable Wordpress XMLRPC & Trackback") {
            $scope.rewriteRules = WordpressProtect + $scope.rewriteRules;
        }
    };


});

/* Java script code to create account ends here */

/* Java script code to suspend/un-suspend Website */

app.controller('suspendWebsiteControl', function ($scope, $http) {

    $scope.suspendLoading = true;
    $scope.stateView = true;

    $scope.websiteSuspendFailure = true;
    $scope.websiteUnsuspendFailure = true;
    $scope.websiteSuccess = true;
    $scope.couldNotConnect = true;

    $scope.showSuspendUnsuspend = function () {

        $scope.stateView = false;


    };

    $scope.save = function () {

        $scope.suspendLoading = false;

        var websiteName = $scope.websiteToBeSuspended
        var state = $scope.state;


        url = "/websites/submitWebsiteStatus";

        var data = {
            websiteName: websiteName,
            state: state,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.websiteStatus === 1) {
                if (state == "Suspend") {

                    $scope.suspendLoading = true;
                    $scope.stateView = false;

                    $scope.websiteSuspendFailure = true;
                    $scope.websiteUnsuspendFailure = true;
                    $scope.websiteSuccess = false;
                    $scope.couldNotConnect = true;

                    $scope.websiteStatus = websiteName;
                    $scope.finalStatus = "Suspended";

                } else {
                    $scope.suspendLoading = true;
                    $scope.stateView = false;

                    $scope.websiteSuspendFailure = true;
                    $scope.websiteUnsuspendFailure = true;
                    $scope.websiteSuccess = false;
                    $scope.couldNotConnect = true;

                    $scope.websiteStatus = websiteName;
                    $scope.finalStatus = "Un-suspended";

                }

            } else {

                if (state == "Suspend") {

                    $scope.suspendLoading = true;
                    $scope.stateView = false;

                    $scope.websiteSuspendFailure = false;
                    $scope.websiteUnsuspendFailure = true;
                    $scope.websiteSuccess = true;
                    $scope.couldNotConnect = true;


                } else {
                    $scope.suspendLoading = true;
                    $scope.stateView = false;

                    $scope.websiteSuspendFailure = true;
                    $scope.websiteUnsuspendFailure = false;
                    $scope.websiteSuccess = true;
                    $scope.couldNotConnect = true;


                }


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {
            $scope.couldNotConnect = false;
            $scope.suspendLoading = true;
            $scope.stateView = true;

            $scope.websiteSuspendFailure = true;
            $scope.websiteUnsuspendFailure = true;
            $scope.websiteSuccess = true;

        }


    };

});

/* Java script code to suspend/un-suspend ends here */

/* Java script code to manage cron */

app.controller('manageCronController', function ($scope, $http) {
    $("#manageCronLoading").hide();
    $("#modifyCronForm").hide();
    $("#cronTable").hide();
    $("#saveCronButton").hide();
    $("#addCronButton").hide();

    $("#addCronFailure").hide();
    $("#cronEditSuccess").hide();
    $("#fetchCronFailure").hide();

    $scope.websiteToBeModified = $("#domain").text();

    $scope.fetchWebsites = function () {

        $("#manageCronLoading").show();
        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();
        var websiteToBeModified = $scope.websiteToBeModified;
        url = "/websites/getWebsiteCron";

        var data = {
            domain: websiteToBeModified,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            if (response.data.getWebsiteCron === 0) {
                console.log(response.data);
                $scope.errorMessage = response.data.error_message;
                $("#cronTable").hide();
                $("#manageCronLoading").hide();
                $("#modifyCronForm").hide();
                $("#saveCronButton").hide();
                $("#addCronButton").hide();
            } else {
                console.log(response.data);
                var finalData = response.data.crons;
                $scope.cronList = finalData;
                $("#cronTable").show();
                $("#manageCronLoading").hide();
                $("#modifyCronForm").hide();
                $("#saveCronButton").hide();
                $("#addCronButton").hide();
            }
        }

        function cantLoadInitialDatas(response) {
            $("#manageCronLoading").hide();
            $("#cronTable").hide();
            $("#fetchCronFailure").show();
            $("#addCronFailure").hide();
            $("#cronEditSuccess").hide();
        }
    };
    $scope.fetchWebsites();

    $scope.fetchCron = function (cronLine) {

        $("#cronTable").show();
        $("#manageCronLoading").show();
        $("#modifyCronForm").show();
        $("#saveCronButton").show();
        $("#addCronButton").hide();

        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();

        $scope.line = cronLine;
        console.log($scope.line);

        var websiteToBeModified = $scope.websiteToBeModified;
        url = "/websites/getCronbyLine";
        var data = {
            domain: websiteToBeModified,
            line: cronLine
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            console.log(response);

            if (response.data.getWebsiteCron === 0) {
                console.log(response.data);
                $scope.errorMessage = response.data.error_message;
                $("#cronTable").show();
                $("#manageCronLoading").hide();
                $("#modifyCronForm").hide();
                $("#saveCronButton").hide();
                $("#addCronButton").hide();
            } else {
                console.log(response.data);

                $scope.minute = response.data.cron.minute
                $scope.hour = response.data.cron.hour
                $scope.monthday = response.data.cron.monthday
                $scope.month = response.data.cron.month
                $scope.weekday = response.data.cron.weekday
                $scope.command = response.data.cron.command
                $scope.line = response.data.line

                $("#cronTable").show();
                $("#manageCronLoading").hide();
                $("#modifyCronForm").fadeIn();
                $("#addCronButton").hide();
                $("#saveCronButton").show();

            }
        }

        function cantLoadInitialDatas(response) {
            $("#manageCronLoading").hide();
            $("#fetchCronFailure").show();
            $("#addCronFailure").hide();
            $("#cronEditSuccess").hide();
        }
    };

    $scope.populate = function () {
        splitTime = $scope.defined.split(" ");
        $scope.minute = splitTime[0];
        $scope.hour = splitTime[1];
        $scope.monthday = splitTime[2];
        $scope.month = splitTime[3];
        $scope.weekday = splitTime[4];
    }

    $scope.addCronForm = function () {

        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();
        $("#manageCronLoading").hide();
        if (!$scope.websiteToBeModified) {
            alert("Please select a domain first");
        } else {
            $scope.minute = $scope.hour = $scope.monthday = $scope.month = $scope.weekday = $scope.command = $scope.line = "";

            $("#cronTable").hide();
            $("#manageCronLoading").hide();
            $("#modifyCronForm").show();
            $("#saveCronButton").hide()
            $("#addCronButton").show();
        }
    };

    $scope.addCronFunc = function () {

        $("#manageCronLoading").show();
        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();

        var websiteToBeModified = $scope.websiteToBeModified;

        url = "/websites/addNewCron";
        var data = {
            domain: websiteToBeModified,
            minute: $scope.minute,
            hour: $scope.hour,
            monthday: $scope.monthday,
            month: $scope.month,
            weekday: $scope.weekday,
            cronCommand: $scope.command
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            console.log(response);

            if (response.data.addNewCron === 0) {
                $scope.errorMessage = response.data.error_message
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").hide();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").show();
            } else {
                $("#cronTable").hide();
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").show();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").hide();

            }
        }

        function cantLoadInitialDatas(response) {
            $("#manageCronLoading").hide();
            $("#addCronFailure").show();
            $("#cronEditSuccess").hide();
            $("#fetchCronFailure").hide();
        }
    };

    $scope.removeCron = function (line) {

        $("#manageCronLoading").show();

        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();

        url = "/websites/remCronbyLine";
        var data = {
            domain: $scope.websiteToBeModified,
            line: line
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            console.log(response);

            if (response.data.remCronbyLine === 0) {
                $scope.errorMessage = response.data.error_message;
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").hide();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").show();
            } else {
                $("#cronTable").hide();
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").show();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").hide();

            }
        }

        function cantLoadInitialDatas(response) {
            $("#manageCronLoading").hide();
            $("#addCronFailure").show();
            $("#cronEditSuccess").hide();
            $("#fetchCronFailure").hide();
        }
    };

    $scope.modifyCronFunc = function () {

        $("#manageCronLoading").show();
        $("#addCronFailure").hide();
        $("#cronEditSuccess").hide();
        $("#fetchCronFailure").hide();

        var websiteToBeModified = $scope.websiteToBeModified;

        url = "/websites/saveCronChanges";
        var data = {
            domain: websiteToBeModified,
            line: $scope.line,
            minute: $scope.minute,
            hour: $scope.hour,
            monthday: $scope.monthday,
            month: $scope.month,
            weekday: $scope.weekday,
            cronCommand: $scope.command
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            if (response.data.addNewCron === 0) {

                $scope.errorMessage = response.data.error_message;
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").hide();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").show();
            } else {
                console.log(response.data);
                $("#cronTable").hide();
                $("#manageCronLoading").hide();
                $("#cronEditSuccess").show();
                $("#fetchCronFailure").hide();
                $("#addCronFailure").hide();

            }
        }

        function cantLoadInitialDatas(response) {
            $("#manageCronLoading").hide();
            $("#addCronFailure").show();
            $("#cronEditSuccess").hide();
            $("#fetchCronFailure").hide();
        }
    };

});

/* Java script code to manage cron ends here */

/* Java script code to manage cron */

app.controller('manageAliasController', function ($scope, $http, $timeout, $window) {

    $('form').submit(function (e) {
        e.preventDefault();
    });

    var masterDomain = "";

    $scope.aliasTable = false;
    $scope.addAliasButton = false;
    $scope.domainAliasForm = true;
    $scope.aliasError = true;
    $scope.couldNotConnect = true;
    $scope.aliasCreated = true;
    $scope.manageAliasLoading = true;
    $scope.operationSuccess = true;

    $scope.createAliasEnter = function ($event) {
        var keyCode = $event.which || $event.keyCode;
        if (keyCode === 13) {
            $scope.manageAliasLoading = false;
            $scope.addAliasFunc();
        }
    };

    $scope.showAliasForm = function (domainName) {

        //$scope.domainAliasForm = false;
        //$scope.aliasTable = true;
        //$scope.addAliasButton = true;

        masterDomain = domainName;

        $scope.showCreateDomainForm();
        $scope.masterDomain = domainName;

    };

    $scope.addAliasFunc = function () {

        $scope.manageAliasLoading = false;

        var ssl;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        url = "/websites/submitAliasCreation";

        var data = {
            masterDomain: masterDomain,
            aliasDomain: $scope.aliasDomain,
            ssl: ssl

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createAliasStatus === 1) {

                $scope.aliasTable = true;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = false;
                $scope.aliasError = true;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = false;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = true;

                $timeout(function () {
                    $window.location.reload();
                }, 3000);


            } else {

                $scope.aliasTable = true;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = false;
                $scope.aliasError = false;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = true;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = true;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {

            $scope.aliasTable = true;
            $scope.addAliasButton = true;
            $scope.domainAliasForm = false;
            $scope.aliasError = true;
            $scope.couldNotConnect = false;
            $scope.aliasCreated = true;
            $scope.manageAliasLoading = true;
            $scope.operationSuccess = true;


        }


    };

    $scope.issueSSL = function (masterDomain, aliasDomain) {

        $scope.manageAliasLoading = false;


        url = "/websites/issueAliasSSL";

        var data = {
            masterDomain: masterDomain,
            aliasDomain: aliasDomain,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.sslStatus === 1) {

                $scope.aliasTable = false;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = true;
                $scope.aliasError = true;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = true;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = false;


            } else {

                $scope.aliasTable = false;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = true;
                $scope.aliasError = false;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = true;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = true;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {

            $scope.aliasTable = false;
            $scope.addAliasButton = true;
            $scope.domainAliasForm = true;
            $scope.aliasError = true;
            $scope.couldNotConnect = false;
            $scope.aliasCreated = true;
            $scope.manageAliasLoading = true;
            $scope.operationSuccess = true;


        }


    };

    $scope.removeAlias = function (masterDomain, aliasDomain) {

        $scope.manageAliasLoading = false;

        url = "/websites/delateAlias";

        var data = {
            masterDomain: masterDomain,
            aliasDomain: aliasDomain,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.deleteAlias === 1) {

                $scope.aliasTable = false;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = true;
                $scope.aliasError = true;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = true;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = false;

                $timeout(function () {
                    $window.location.reload();
                }, 3000);


            } else {

                $scope.aliasTable = false;
                $scope.addAliasButton = true;
                $scope.domainAliasForm = true;
                $scope.aliasError = false;
                $scope.couldNotConnect = true;
                $scope.aliasCreated = true;
                $scope.manageAliasLoading = true;
                $scope.operationSuccess = true;

                $scope.errorMessage = response.data.error_message;

            }

        }

        function cantLoadInitialDatas(response) {

            $scope.aliasTable = false;
            $scope.addAliasButton = true;
            $scope.domainAliasForm = true;
            $scope.aliasError = true;
            $scope.couldNotConnect = false;
            $scope.aliasCreated = true;
            $scope.manageAliasLoading = true;
            $scope.operationSuccess = true;


        }


    };


    ////// create domain part

    $("#domainCreationForm").hide();

    $scope.showCreateDomainForm = function () {
        $("#domainCreationForm").fadeIn();
    };

    $scope.hideDomainCreationForm = function () {
        $("#domainCreationForm").fadeOut();
    };

    $scope.masterDomain = $("#domainNamePage").text();

    // notifcations settings
    $scope.domainLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;
    $scope.DomainCreateForm = true;

    var statusFile;


    $scope.webselection = true;
    $scope.WebsiteType = function () {
        var type = $scope.websitetype;
        if (type == 'Sub Domain') {
            $scope.webselection = false;
            $scope.DomainCreateForm = true;

        } else if (type == 'Addon Domain') {
            $scope.DomainCreateForm = false;
            $scope.webselection = true;
            $scope.masterDomain = $('#defaultSite').html()
        }
    };

    $scope.WebsiteSelection = function () {
        $scope.DomainCreateForm = false;
    };

    $scope.createDomain = function () {

        $scope.domainLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting creation..";
        $scope.DomainCreateForm = true;

        var ssl, dkimCheck, openBasedir, apacheBackend;

        if ($scope.sslCheck === true) {
            ssl = 1;
        } else {
            ssl = 0
        }

        if ($scope.dkimCheck === true) {
            dkimCheck = 1;
        } else {
            dkimCheck = 0
        }

        openBasedir = 0;


        apacheBackend = 0


        url = "/websites/submitDomainCreation";
        var domainName = $scope.domainNameCreate;

        var path = $scope.docRootPath;

        if (typeof path === 'undefined') {
            path = "";
        }

        var domainName = $scope.domainNameCreate;


        var data = {
            domainName: domainName,
            ssl: ssl,
            path: path,
            masterDomain: $scope.masterDomain,
            dkimCheck: 1,
            openBasedir: 0,
            alias: 1
        };


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        // console.log(data)

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.createWebSiteStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.domainLoading = true;
                $scope.installationDetailsForm = true;
                $scope.DomainCreateForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;
            $scope.installationDetailsForm = true;
            $scope.DomainCreateForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };

    $scope.goBack = function () {
        $scope.domainLoading = true;
        $scope.installationDetailsForm = false;
        $scope.DomainCreateForm = true;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $scope.DomainCreateForm = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.domainLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    fetchDomains();

                } else {

                    $scope.domainLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.DomainCreateForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;
            $scope.installationDetailsForm = true;
            $scope.DomainCreateForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }


    ////// List Domains Part

    ////////////////////////

    // notifcations

    $scope.phpChanged = true;
    $scope.domainError = true;
    $scope.couldNotConnect = true;
    $scope.domainDeleted = true;
    $scope.sslIssued = true;
    $scope.childBaseDirChanged = true;

    fetchDomains();

    $scope.showListDomains = function () {
        fetchDomains();
        $("#listDomains").fadeIn();
    };

    $scope.hideListDomains = function () {
        $("#listDomains").fadeOut();
    };

    function fetchDomains() {
        $scope.domainLoading = false;

        var url = "/websites/fetchDomains";

        var data = {
            masterDomain: $("#domainNamePage").text(),
            alias: 1
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.fetchStatus === 1) {

                $scope.childDomains = JSON.parse(response.data.data);
                $scope.domainLoading = true;


            } else {
                $scope.domainError = false;
                $scope.errorMessage = response.data.error_message;
                $scope.domainLoading = true;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.couldNotConnect = false;

        }

    }

    $scope.changePHP = function (childDomain, phpSelection) {

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;
        $scope.domainLoading = false;
        $scope.childBaseDirChanged = true;

        var url = "/websites/changePHP";

        var data = {
            childDomain: childDomain,
            phpSelection: phpSelection,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changePHP === 1) {

                $scope.domainLoading = true;

                $scope.changedPHPVersion = phpSelection;


                // notifcations

                $scope.phpChanged = false;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.childBaseDirChanged = true;


            } else {
                $scope.errorMessage = response.data.error_message;
                $scope.domainLoading = true;

                // notifcations

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.childBaseDirChanged = true;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.domainLoading = true;

            // notifcations

            $scope.phpChanged = true;
            $scope.domainError = false;
            $scope.couldNotConnect = true;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;
            $scope.childBaseDirChanged = true;

        }

    };

    $scope.changeChildBaseDir = function (childDomain, openBasedirValue) {

        // notifcations

        $scope.phpChanged = true;
        $scope.domainError = true;
        $scope.couldNotConnect = true;
        $scope.domainDeleted = true;
        $scope.sslIssued = true;
        $scope.domainLoading = false;
        $scope.childBaseDirChanged = true;


        var url = "/websites/changeOpenBasedir";

        var data = {
            domainName: childDomain,
            openBasedirValue: openBasedirValue
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changeOpenBasedir === 1) {

                $scope.phpChanged = true;
                $scope.domainError = true;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.domainLoading = true;
                $scope.childBaseDirChanged = false;

            } else {

                $scope.phpChanged = true;
                $scope.domainError = false;
                $scope.couldNotConnect = true;
                $scope.domainDeleted = true;
                $scope.sslIssued = true;
                $scope.domainLoading = true;
                $scope.childBaseDirChanged = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.phpChanged = true;
            $scope.domainError = true;
            $scope.couldNotConnect = false;
            $scope.domainDeleted = true;
            $scope.sslIssued = true;
            $scope.domainLoading = true;
            $scope.childBaseDirChanged = true;


        }

    }

    $scope.showWPSites = function(domain) {
        console.log('showWPSites called for domain:', domain);
        
        // Make sure domain is defined
        if (!domain) {
            console.error('Domain is undefined');
            return;
        }

        // Find the website in the list
        var site = $scope.WebSitesList.find(function(website) {
            return website.domain === domain;
        });

        if (!site) {
            console.error('Website not found:', domain);
            return;
        }

        // Set loading state
        site.loadingWPSites = true;

        // Toggle visibility
        site.showWPSites = !site.showWPSites;
        
        // If we're hiding, just return
        if (!site.showWPSites) {
            site.loadingWPSites = false;
            return;
        }

        var config = {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = $.param({
            domain: domain
        });

        $http.post('/websites/fetchWPDetails', data, config)
            .then(function(response) {
                console.log('Response received:', response);
                if (response.data.status === 1 && response.data.fetchStatus === 1) {
                    site.wp_sites = response.data.sites || [];
                    // Initialize loading states for each WP site
                    site.wp_sites.forEach(function(wp) {
                        wp.loading = false;
                        wp.loadingPlugins = false;
                        wp.loadingTheme = false;
                    });
                    $("#listFail").hide();
                } else {
                    $("#listFail").fadeIn();
                    site.showWPSites = false;
                    $scope.errorMessage = response.data.error_message || 'Failed to fetch WordPress sites';
                    console.error('Error in response:', response.data.error_message);
                    new PNotify({
                        title: 'Error!',
                        text: response.data.error_message || 'Failed to fetch WordPress sites',
                        type: 'error'
                    });
                }
            })
            .catch(function(error) {
                console.error('Request failed:', error);
                site.showWPSites = false;
                $("#listFail").fadeIn();
                $scope.errorMessage = error.message || 'An error occurred while fetching WordPress sites';
                new PNotify({
                    title: 'Error!',
                    text: error.message || 'Could not connect to server',
                    type: 'error'
                });
            })
            .finally(function() {
                site.loadingWPSites = false;
            });
    };

    $scope.updateSetting = function(wp, setting) {
        var settingMap = {
            'search-indexing': 'searchIndex',
            'debugging': 'debugging',
            'password-protection': 'passwordProtection',
            'maintenance-mode': 'maintenanceMode'
        };

        // Toggle the state before sending request
        wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;

        var data = {
            siteId: wp.id,
            setting: setting,
            value: wp[settingMap[setting]]
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post('/websites/UpdateWPSettings', data, config).then(function(response) {
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Setting updated successfully.',
                    type: 'success'
                });
                if (setting === 'password-protection' && wp[settingMap[setting]] === 1) {
                    // Show password protection modal if enabling
                    wp.PPUsername = "";
                    wp.PPPassword = "";
                    $scope.currentWP = wp;
                    $('#passwordProtectionModal').modal('show');
                }
            } else {
                // Revert the change if update failed
                wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
                new PNotify({
                    title: 'Error',
                    text: response.data.error_message || 'Failed to update setting.',
                    type: 'error'
                });
            }
        }).catch(function(error) {
            // Revert the change on error
            wp[settingMap[setting]] = wp[settingMap[setting]] === 1 ? 0 : 1;
            new PNotify({
                title: 'Error',
                text: 'Connection failed while updating setting.',
                type: 'error'
            });
        });
    };

    $scope.visitSite = function(wp) {
        var url = wp.url || wp.domain;
        if (!url) return;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        window.open(url, '_blank');
    };

    $scope.wpLogin = function(wpId) {
        window.open('/websites/wpLogin?wpID=' + wpId, '_blank');
    };

    $scope.manageWP = function(wpId) {
        window.location.href = '/websites/listWPsites?wpID=' + wpId;
    };

    $scope.saveRewriteRules = function () {

        $scope.configFileLoading = false;


        url = "/websites/saveRewriteRules";

        var virtualHost = $("#childDomain").text();
        var rewriteRules = $scope.rewriteRules;


        var data = {
            virtualHost: virtualHost,
            rewriteRules: rewriteRules,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.rewriteStatus == 1) {

                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = false;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;
                $scope.configFileLoading = true;


            } else {
                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = false;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = false;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = false;

                $scope.configFileLoading = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configurationsBoxRewrite = false;
            $scope.rewriteRulesFetched = false;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = false;

            $scope.configFileLoading = true;

            $scope.couldNotConnect = false;


        }


    };


    //////// SSL Part

    $scope.sslSaved = true;
    $scope.couldNotSaveSSL = true;
    $scope.hidsslconfigs = true;
    $scope.couldNotConnect = true;


    $scope.hidesslbtn = function () {
        $scope.hidsslconfigs = true;
    };

    $scope.addSSL = function () {
        $scope.hidsslconfigs = false;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = true;
    };


    $scope.saveSSL = function () {


        $scope.configFileLoading = false;

        url = "/websites/saveSSL";

        var virtualHost = $("#childDomain").text();
        var cert = $scope.cert;
        var key = $scope.key;


        var data = {
            virtualHost: virtualHost,
            cert: cert,
            key: key,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.sslStatus === 1) {

                $scope.sslSaved = false;
                $scope.couldNotSaveSSL = true;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;


            } else {

                $scope.sslSaved = true;
                $scope.couldNotSaveSSL = false;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.sslSaved = true;
            $scope.couldNotSaveSSL = true;
            $scope.couldNotConnect = false;
            $scope.configFileLoading = true;


        }

    };


    //// Change PHP Master

    $scope.failedToChangePHPMaster = true;
    $scope.phpChangedMaster = true;
    $scope.couldNotConnect = true;

    $scope.changePHPView = true;


    $scope.hideChangePHPMaster = function () {
        $scope.changePHPView = true;
    };

    $scope.changePHPMaster = function () {
        $scope.hidsslconfigs = true;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = false;
    };


    $scope.changePHPVersionMaster = function (childDomain, phpSelection) {

        // notifcations

        $scope.configFileLoading = false;

        var url = "/websites/changePHP";

        var data = {
            childDomain: $("#childDomain").text(),
            phpSelection: $scope.phpSelectionMaster,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changePHP === 1) {

                $scope.configFileLoading = true;
                $scope.websiteDomain = $("#childDomain").text();


                // notifcations

                $scope.failedToChangePHPMaster = true;
                $scope.phpChangedMaster = false;
                $scope.couldNotConnect = true;


            } else {

                $scope.configFileLoading = true;
                $scope.errorMessage = response.data.error_message;

                // notifcations

                $scope.failedToChangePHPMaster = false;
                $scope.phpChangedMaster = true;
                $scope.couldNotConnect = true;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configFileLoading = true;

            // notifcations

            $scope.failedToChangePHPMaster = true;
            $scope.phpChangedMaster = true;
            $scope.couldNotConnect = false;

        }

    };


    /// Open_basedir protection

    $scope.baseDirLoading = true;
    $scope.operationFailed = true;
    $scope.operationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.openBaseDirBox = true;


    $scope.openBaseDirView = function () {
        $scope.openBaseDirBox = false;
    };

    $scope.hideOpenBasedir = function () {
        $scope.openBaseDirBox = true;
    };

    $scope.applyOpenBasedirChanges = function (childDomain, phpSelection) {

        // notifcations

        $scope.baseDirLoading = false;
        $scope.operationFailed = true;
        $scope.operationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.openBaseDirBox = false;


        var url = "/websites/changeOpenBasedir";

        var data = {
            domainName: $("#childDomain").text(),
            openBasedirValue: $scope.openBasedirValue
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changeOpenBasedir === 1) {

                $scope.baseDirLoading = true;
                $scope.operationFailed = true;
                $scope.operationSuccessfull = false;
                $scope.couldNotConnect = true;
                $scope.openBaseDirBox = false;

            } else {

                $scope.baseDirLoading = true;
                $scope.operationFailed = false;
                $scope.operationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.openBaseDirBox = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.baseDirLoading = true;
            $scope.operationFailed = true;
            $scope.operationSuccessfull = true;
            $scope.couldNotConnect = false;
            $scope.openBaseDirBox = false;


        }

    }

});

/* Application Installer */

app.controller('installWordPressCTRL', function ($scope, $http, $timeout) {

    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.wpInstallLoading = true;
    $scope.goBackDisable = true;

    var statusFile;
    var domain = $("#domainNamePage").text();
    var path;


    $scope.goBack = function () {
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    $scope.installWordPress = function () {

        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = false;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting installation..";

        path = $scope.installPath;


        url = "/websites/installWordpress";

        var home = "1";

        if (typeof path !== 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            home: home,
            path: path,
            blogTitle: $scope.blogTitle,
            adminUser: $scope.adminUser,
            passwordByPass: $scope.adminPassword,
            adminEmail: $scope.adminEmail
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getInstallStatus();
            } else {

                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.wpInstallLoading = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {


        }

    };

    function getInstallStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile,
            domainName: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = true;
                    $scope.installationSuccessfull = false;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    if (typeof path !== 'undefined') {
                        $scope.installationURL = "http://" + domain + "/" + path;
                    } else {
                        $scope.installationURL = domain;
                    }


                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = false;
                    $scope.installationSuccessfull = true;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;

                $timeout(getInstallStatus, 1000);


            }

        }

        function cantLoadInitialDatas(response) {

            $scope.canNotFetch = true;
            $scope.couldNotConnect = false;


        }


    }


});

app.controller('installJoomlaCTRL', function ($scope, $http, $timeout) {

    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.wpInstallLoading = true;
    $scope.goBackDisable = true;

    $scope.databasePrefix = 'jm_';

    var statusFile;
    var domain = $("#domainNamePage").text();
    var path;


    $scope.goBack = function () {
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getInstallStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile,
            domainName: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = true;
                    $scope.installationSuccessfull = false;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    if (typeof path !== 'undefined') {
                        $scope.installationURL = "http://" + domain + "/" + path;
                    } else {
                        $scope.installationURL = domain;
                    }


                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = false;
                    $scope.installationSuccessfull = true;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;

                $timeout(getInstallStatus, 1000);


            }

        }

        function cantLoadInitialDatas(response) {

            $scope.canNotFetch = true;
            $scope.couldNotConnect = false;


        }


    }

    $scope.installJoomla = function () {

        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = false;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting installation..";

        path = $scope.installPath;


        url = "/websites/installJoomla";

        var home = "1";

        if (typeof path !== 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            home: home,
            path: path,
            siteName: $scope.siteName,
            username: $scope.adminUser,
            passwordByPass: $scope.adminPassword,
            prefix: $scope.databasePrefix
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getInstallStatus();
            } else {

                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.wpInstallLoading = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {


        }

    };


});

app.controller('setupGit', function ($scope, $http, $timeout, $window) {

    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.gitLoading = true;
    $scope.githubBranch = 'master';
    $scope.installProg = true;
    $scope.goBackDisable = true;

    var defaultProvider = 'github';

    $scope.setProvider = function (provider) {
        defaultProvider = provider;
    };


    var statusFile;
    var domain = $("#domainNamePage").text();

    function getInstallStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile,
            domainName: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = true;
                    $scope.installationSuccessfull = false;
                    $scope.couldNotConnect = true;
                    $scope.gitLoading = true;
                    $scope.goBackDisable = true;

                    $scope.installationURL = domain;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();
                    $timeout(function () {
                        $window.location.reload();
                    }, 3000);

                } else {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = false;
                    $scope.installationSuccessfull = true;
                    $scope.couldNotConnect = true;
                    $scope.gitLoading = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;

                $timeout(getInstallStatus, 1000);


            }

        }

        function cantLoadInitialDatas(response) {

            $scope.canNotFetch = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;


        }


    }

    $scope.attachRepo = function () {

        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.gitLoading = false;
        $scope.installProg = false;

        $scope.currentStatus = "Attaching GIT..";

        url = "/websites/setupGitRepo";

        var data = {
            domain: domain,
            username: $scope.githubUserName,
            reponame: $scope.githubRepo,
            branch: $scope.githubBranch,
            defaultProvider: defaultProvider
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getInstallStatus();
            } else {

                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.gitLoading = true;

                $scope.errorMessage = response.data.error_message;
                $scope.goBackDisable = false;

            }


        }

        function cantLoadInitialDatas(response) {


        }

    };

    $scope.goBack = function () {
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.installProg = true;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.gitLoading = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    /// Detach Repo

    $scope.failedMesg = true;
    $scope.successMessage = true;
    $scope.couldNotConnect = true;
    $scope.gitLoading = true;
    $scope.successMessageBranch = true;

    $scope.detachRepo = function () {

        $scope.failedMesg = true;
        $scope.successMessage = true;
        $scope.couldNotConnect = true;
        $scope.gitLoading = false;
        $scope.successMessageBranch = true;

        url = "/websites/detachRepo";

        var data = {
            domain: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            $scope.gitLoading = true;

            if (response.data.status === 1) {
                $scope.failedMesg = true;
                $scope.successMessage = false;
                $scope.couldNotConnect = true;
                $scope.successMessageBranch = true;

                $timeout(function () {
                    $window.location.reload();
                }, 3000);

            } else {

                $scope.failedMesg = false;
                $scope.successMessage = true;
                $scope.couldNotConnect = true;
                $scope.successMessageBranch = true;

                $scope.errorMessage = response.data.error_message;


            }


        }

        function cantLoadInitialDatas(response) {
            $scope.failedMesg = true;
            $scope.successMessage = true;
            $scope.couldNotConnect = false;
            $scope.gitLoading = true;
            $scope.successMessageBranch = true;
        }

    };
    $scope.changeBranch = function () {

        $scope.failedMesg = true;
        $scope.successMessage = true;
        $scope.couldNotConnect = true;
        $scope.gitLoading = false;
        $scope.successMessageBranch = true;

        url = "/websites/changeBranch";

        var data = {
            domain: domain,
            githubBranch: $scope.githubBranch
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            $scope.gitLoading = true;

            if (response.data.status === 1) {
                $scope.failedMesg = true;
                $scope.successMessage = true;
                $scope.couldNotConnect = true;
                $scope.successMessageBranch = false;

            } else {

                $scope.failedMesg = false;
                $scope.successMessage = true;
                $scope.couldNotConnect = true;
                $scope.successMessageBranch = true;

                $scope.errorMessage = response.data.error_message;


            }


        }

        function cantLoadInitialDatas(response) {
            $scope.failedMesg = true;
            $scope.successMessage = true;
            $scope.couldNotConnect = false;
            $scope.gitLoading = true;
            $scope.successMessageBranch = true;
        }

    };


});

app.controller('installPrestaShopCTRL', function ($scope, $http, $timeout) {

    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.wpInstallLoading = true;
    $scope.goBackDisable = true;

    $scope.databasePrefix = 'ps_';

    var statusFile;
    var domain = $("#domainNamePage").text();
    var path;


    $scope.goBack = function () {
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getInstallStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile,
            domainName: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = true;
                    $scope.installationSuccessfull = false;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    if (typeof path !== 'undefined') {
                        $scope.installationURL = "http://" + domain + "/" + path;
                    } else {
                        $scope.installationURL = domain;
                    }


                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = false;
                    $scope.installationSuccessfull = true;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;

                $timeout(getInstallStatus, 1000);


            }

        }

        function cantLoadInitialDatas(response) {

            $scope.canNotFetch = true;
            $scope.couldNotConnect = false;


        }


    }

    $scope.installPrestShop = function () {

        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = false;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting installation..";

        path = $scope.installPath;


        url = "/websites/prestaShopInstall";

        var home = "1";

        if (typeof path !== 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            home: home,
            path: path,
            shopName: $scope.shopName,
            firstName: $scope.firstName,
            lastName: $scope.lastName,
            databasePrefix: $scope.databasePrefix,
            email: $scope.email,
            passwordByPass: $scope.password
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getInstallStatus();
            } else {

                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.wpInstallLoading = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {
        }

    };


});

app.controller('installMauticCTRL', function ($scope, $http, $timeout) {

    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.installationFailed = true;
    $scope.installationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.wpInstallLoading = true;
    $scope.goBackDisable = true;

    $scope.databasePrefix = 'ps_';

    var statusFile;
    var domain = $("#domainNamePage").text();
    var path;


    $scope.goBack = function () {
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getInstallStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile,
            domainName: domain
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = true;
                    $scope.installationSuccessfull = false;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    if (typeof path !== 'undefined') {
                        $scope.installationURL = "http://" + domain + "/" + path;
                    } else {
                        $scope.installationURL = domain;
                    }


                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.installationFailed = false;
                    $scope.installationSuccessfull = true;
                    $scope.couldNotConnect = true;
                    $scope.wpInstallLoading = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;

                $timeout(getInstallStatus, 1000);


            }

        }

        function cantLoadInitialDatas(response) {

            $scope.canNotFetch = true;
            $scope.couldNotConnect = false;


        }


    }

    $scope.installMautic = function () {

        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.installationFailed = true;
        $scope.installationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.wpInstallLoading = false;
        $scope.goBackDisable = true;
        $scope.currentStatus = "Starting installation..";

        path = $scope.installPath;


        url = "/websites/mauticInstall";

        var home = "1";

        if (typeof path !== 'undefined') {
            home = "0";
        }


        var data = {
            domain: domain,
            home: home,
            path: path,
            username: $scope.adminUserName,
            email: $scope.email,
            passwordByPass: $scope.password
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.installStatus === 1) {
                statusFile = response.data.tempStatusPath;
                getInstallStatus();
            } else {

                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.installationFailed = false;
                $scope.installationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.wpInstallLoading = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {
        }

    };


});

app.controller('sshAccess', function ($scope, $http, $timeout) {

    $scope.openWebTerminal = function() {
        $('#web-terminal-modal').modal('show');
    
        if ($scope.term) {
            $scope.term.dispose();
        }
        var term = new Terminal({
            cursorBlink: true,
            fontFamily: 'monospace',
            fontSize: 14,
            theme: { background: '#000' }
        });
        $scope.term = term;
        term.open(document.getElementById('xterm-container'));
        term.focus();
    
        // Fetch JWT from backend with CSRF token
        var domain = $("#domainName").text();
        var csrftoken = getCookie('csrftoken');
        $http.post('/websites/getTerminalJWT', { domain: domain }, {
            headers: { 'X-CSRFToken': csrftoken }
        })
        .then(function(response) {
            if (response.data.status === 1 && response.data.token) {
                var token = response.data.token;
                var ssh_user = $("#externalApp").text();
                var wsProto = location.protocol === 'https:' ? 'wss' : 'ws';
                var wsUrl = wsProto + '://' + window.location.hostname + ':8888/ws?token=' + encodeURIComponent(token) + '&ssh_user=' + encodeURIComponent(ssh_user);
                var socket = new WebSocket(wsUrl);
                socket.binaryType = 'arraybuffer';
                $scope.terminalSocket = socket;
    
                socket.onopen = function() {
                    term.write('\x1b[32mConnected.\x1b[0m\r\n');
                };
                socket.onclose = function() {
                    term.write('\r\n\x1b[31mConnection closed.\x1b[0m\r\n');
                };
                socket.onerror = function(e) {
                    term.write('\r\n\x1b[31mWebSocket error.\x1b[0m\r\n');
                };
                socket.onmessage = function(event) {
                    if (event.data instanceof ArrayBuffer) {
                        var text = new Uint8Array(event.data);
                        term.write(new TextDecoder().decode(text));
                    } else if (typeof event.data === 'string') {
                        term.write(event.data);
                    }
                };
                term.onData(function(data) {
                    if (socket.readyState === WebSocket.OPEN) {
                        var encoder = new TextEncoder();
                        socket.send(encoder.encode(data));
                    }
                });
                term.onResize(function(size) {
                    if (socket.readyState === WebSocket.OPEN) {
                        var msg = JSON.stringify({resize: {cols: size.cols, rows: size.rows}});
                        socket.send(msg);
                    }
                });
                $('#web-terminal-modal').on('hidden.bs.modal', function() {
                    if ($scope.term) {
                        $scope.term.dispose();
                        $scope.term = null;
                    }
                    if ($scope.terminalSocket) {
                        $scope.terminalSocket.close();
                        $scope.terminalSocket = null;
                    }
                });
            } else {
                term.write('\x1b[31mFailed to get terminal token.\x1b[0m\r\n');
            }
        }, function() {
            term.write('\x1b[31mFailed to contact backend.\x1b[0m\r\n');
        });
    };

    $scope.wpInstallLoading = true;

    $scope.setupSSHAccess = function () {
        $scope.wpInstallLoading = false;

        url = "/websites/saveSSHAccessChanges";

        var data = {
            domain: $("#domainName").text(),
            externalApp: $("#externalApp").text(),
            password: $scope.password
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.wpInstallLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes Successfully Applied.',
                    type: 'success'
                });
            } else {


                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }


        }

        function cantLoadInitialDatas(response) {

            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }

    };

    /// SSH Key at user level

    $scope.keyBox = true;
    $scope.saveKeyBtn = true;

    $scope.addKey = function () {
        $scope.showKeyBox = true;
        $scope.keyBox = false;
        $scope.saveKeyBtn = false;
    };

    function populateCurrentKeys() {

        url = "/websites/getSSHConfigs";

        var data = {
            domain: $("#domainName").text(),
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                $scope.records = JSON.parse(response.data.data);
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.couldNotConnect = false;
        }


    }

    populateCurrentKeys();

    $scope.deleteKey = function (key) {

        $scope.wpInstallLoading = false;

        url = "/websites/deleteSSHKey";

        var data = {
            domain: $("#domainName").text(),
            key: key,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.wpInstallLoading = true;
            if (response.data.delete_status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Key deleted successfully.',
                    type: 'success'
                });
                populateCurrentKeys();
            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            $scope.wpInstallLoading = true;
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });

        }


    }

    $scope.saveKey = function (key) {

        $scope.wpInstallLoading = false;

        url = "/websites/addSSHKey";

        var data = {
            domain: $("#domainName").text(),
            key: $scope.keyData,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            $scope.wpInstallLoading = true;
            if (response.data.add_status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Key added successfully.',
                    type: 'success'
                });
                populateCurrentKeys();
            } else {
                new PNotify({
                    title: 'Error!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialDatas(response) {
            new PNotify({
                title: 'Error!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });

        }


    }


});


/* Java script code to cloneWebsite */
app.controller('cloneWebsite', function ($scope, $http, $timeout, $window) {

    $('form').submit(function (e) {
        e.preventDefault();
    });

    $scope.cyberpanelLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.goBackDisable = true;

    $scope.cloneEnter = function ($event) {
        var keyCode = $event.which || $event.keyCode;
        if (keyCode === 13) {
            $scope.cyberpanelLoading = false;
            $scope.startCloning();
        }
    };

    var statusFile;

    $scope.startCloning = function () {

        $scope.cyberpanelLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Cloning started..";

        url = "/websites/startCloning";


        var data = {
            masterDomain: $("#domainName").text(),
            domainName: $scope.domain

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {

            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.cyberpanelLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.goBackDisable = false;

                $scope.currentStatus = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.cyberpanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }

    };
    $scope.goBack = function () {
        $scope.cyberpanelLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.cyberpanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.cyberpanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.goBackDisable = false;

                    $scope.currentStatus = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.cyberpanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.goBackDisable = false;

        }


    }

});
/* Java script code to cloneWebsite ends here */

/* Java script code to git tracking */
app.controller('manageGIT', function ($scope, $http, $timeout, $window) {

    $scope.cyberpanelLoading = true;
    $scope.loadingSticks = true;
    $scope.gitTracking = true;
    $scope.gitEnable = true;
    $scope.statusBox = true;
    $scope.gitCommitsTable = true;

    var statusFile;

    $scope.fetchFolderDetails = function () {

        $scope.cyberpanelLoading = false;
        $scope.gitCommitsTable = true;

        url = "/websites/fetchFolderDetails";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                if (response.data.repo === 1) {
                    $scope.gitTracking = true;
                    $scope.gitEnable = false;
                    $scope.branches = response.data.finalBranches;
                    $scope.deploymentKey = response.data.deploymentKey;
                    $scope.remote = response.data.remote;
                    $scope.remoteResult = response.data.remoteResult;
                    $scope.totalCommits = response.data.totalCommits;
                    $scope.home = response.data.home;
                    $scope.webHookURL = response.data.webHookURL;
                    $scope.autoCommitCurrent = response.data.autoCommitCurrent;
                    $scope.autoPushCurrent = response.data.autoPushCurrent;
                    $scope.emailLogsCurrent = response.data.emailLogsCurrent;
                    document.getElementById("currentCommands").value = response.data.commands;
                    $scope.webhookCommandCurrent = response.data.webhookCommandCurrent;
                } else {
                    $scope.gitTracking = false;
                    $scope.gitEnable = true;
                    $scope.home = response.data.home;
                    $scope.deploymentKey = response.data.deploymentKey;
                }
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }

    };

    $scope.initRepo = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/initRepo";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Repo initiated.',
                    type: 'success'
                });
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }

    };

    $scope.setupRemote = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/setupRemote";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            gitHost: $scope.gitHost,
            gitUsername: $scope.gitUsername,
            gitReponame: $scope.gitReponame,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Remote successfully set.',
                    type: 'success'
                });
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }

    };

    var changeBranch = 0;

    $scope.changeBranch = function () {

        if (changeBranch === 1) {
            changeBranch = 0;
            return 0;
        }

        $scope.loadingSticks = false;
        $("#showStatus").modal();

        url = "/websites/changeGitBranch";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            branchName: $scope.branchName

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.loadingSticks = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
                $timeout(function () {
                    $window.location.reload();
                }, 3000);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.loadingSticks = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.createNewBranch = function () {
        $scope.cyberpanelLoading = false;
        $scope.commandStatus = "";
        $scope.statusBox = false;
        changeBranch = 1;

        url = "/websites/createNewBranch";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            newBranchName: $scope.newBranchName

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = false;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.commitChanges = function () {
        $scope.cyberpanelLoading = false;
        $scope.commandStatus = "";
        $scope.statusBox = false;

        url = "/websites/commitChanges";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            commitMessage: $scope.commitMessage

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = false;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.gitPull = function () {

        $scope.loadingSticks = false;
        $("#showStatus").modal();

        url = "/websites/gitPull";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.loadingSticks = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.loadingSticks = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.gitPush = function () {

        $scope.loadingSticks = false;
        $("#showStatus").modal();

        url = "/websites/gitPush";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.loadingSticks = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.loadingSticks = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.attachRepoGIT = function () {
        $scope.cyberpanelLoading = false;
        $scope.commandStatus = "";
        $scope.statusBox = false;

        url = "/websites/attachRepoGIT";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            gitHost: $scope.gitHost,
            gitUsername: $scope.gitUsername,
            gitReponame: $scope.gitReponame,
            overrideData: $scope.overrideData
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;

            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.commandStatus = response.data.commandStatus;
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
                $scope.commandStatus = response.data.commandStatus;
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = false;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.removeTracking = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/removeTracking";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Changes applied.',
                    type: 'success'
                });
                $scope.fetchFolderDetails();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.fetchGitignore = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/fetchGitignore";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully fetched.',
                    type: 'success'
                });
                $scope.gitIgnoreContent = response.data.gitIgnoreContent;
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.saveGitIgnore = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/saveGitIgnore";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            gitIgnoreContent: $scope.gitIgnoreContent

        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully saved.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.fetchCommits = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/fetchCommits";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            $scope.gitCommitsTable = false;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully fetched.',
                    type: 'success'
                });
                $scope.commits = JSON.parse(response.data.commits);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    var currentComit;
    var fetchFileCheck = 0;
    var initial = 1;

    $scope.fetchFiles = function (commit) {

        currentComit = commit;
        $scope.cyberpanelLoading = false;

        if (initial === 1) {
            initial = 0;
        } else {
            fetchFileCheck = 1;
        }

        url = "/websites/fetchFiles";


        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            commit: commit
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            $scope.gitCommitsTable = false;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully fetched.',
                    type: 'success'
                });
                $scope.files = response.data.files;
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }


        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.fileStatus = true;

    $scope.fetchChangesInFile = function () {
        $scope.fileStatus = true;

        if (fetchFileCheck === 1) {
            fetchFileCheck = 0;
            return 0;
        }

        $scope.cyberpanelLoading = false;
        $scope.currentSelectedFile = $scope.changeFile;

        url = "/websites/fetchChangesInFile";

        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            file: $scope.changeFile,
            commit: currentComit
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully fetched.',
                    type: 'success'
                });
                $scope.fileStatus = false;
                document.getElementById("fileChangedContent").innerHTML = response.data.fileChangedContent;
            } else {
                $scope.fileStatus = true;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.saveGitConfigurations = function () {

        $scope.cyberpanelLoading = false;

        url = "/websites/saveGitConfigurations";

        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            autoCommit: $scope.autoCommit,
            autoPush: $scope.autoPush,
            emailLogs: $scope.emailLogs,
            commands: document.getElementById("currentCommands").value,
            webhookCommand: $scope.webhookCommand
        };

        if ($scope.autoCommit === undefined) {
            $scope.autoCommitCurrent = 'Never';
        } else {
            $scope.autoCommitCurrent = $scope.autoCommit;
        }

        if ($scope.autoPush === undefined) {
            $scope.autoPushCurrent = 'Never';
        } else {
            $scope.autoPushCurrent = $scope.autoPush;
        }

        if ($scope.emailLogs === undefined) {
            $scope.emailLogsCurrent = false;
        } else {
            $scope.emailLogsCurrent = $scope.emailLogs;
        }

        if ($scope.webhookCommand === undefined) {
            $scope.webhookCommandCurrent = false;
        } else {
            $scope.webhookCommandCurrent = $scope.webhookCommand;
        }

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully saved.',
                    type: 'success'
                });
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    };

    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    $scope.fetchGitLogs = function () {
        $scope.cyberpanelLoading = false;
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            domain: $("#domain").text(),
            folder: $scope.folder,
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };


        dataurl = "/websites/fetchGitLogs";

        $http.post(dataurl, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully fetched.',
                    type: 'success'
                });
                $scope.logs = JSON.parse(response.data.logs);
                $scope.pagination = response.data.pagination;
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }


    };

});

/* Java script code to git tracking ends here */


app.controller('ApacheManager', function ($scope, $http, $timeout) {
    $scope.cyberpanelloading = true;
    $scope.apacheOLS = true;
    $scope.pureOLS = true;
    $scope.lswsEnt = true;

    var apache = 1, ols = 2, lsws = 3;
    var statusFile;

    $scope.getSwitchStatus = function () {
        $scope.cyberpanelloading = false;
        url = "/websites/getSwitchStatus";

        var data = {
            domainName: $("#domainNamePage").text()
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            $scope.cyberpanelloading = true;
            if (response.data.status === 1) {
                if (response.data.server === apache) {
                    $scope.apacheOLS = false;
                    $scope.pureOLS = true;
                    $scope.lswsEnt = true;
                    $scope.configData = response.data.configData;

                    $scope.pmMaxChildren = response.data.pmMaxChildren;
                    $scope.pmStartServers = response.data.pmStartServers;
                    $scope.pmMinSpareServers = response.data.pmMinSpareServers;
                    $scope.pmMaxSpareServers = response.data.pmMaxSpareServers;
                    $scope.phpPath = response.data.phpPath;


                } else if (response.data.server === ols) {
                    $scope.apacheOLS = true;
                    $scope.pureOLS = false;
                    $scope.lswsEnt = true;
                } else {
                    $scope.apacheOLS = true;
                    $scope.pureOLS = true;
                    $scope.lswsEnt = false;
                }
                //$scope.records = JSON.parse(response.data.data);
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialData(response) {
            $scope.cyberpanelloading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });
        }


    };
    $scope.getSwitchStatus();

    $scope.switchServer = function (server) {
        $scope.cyberpanelloading = false;
        $scope.functionProgress = {"width": "0%"};
        $scope.functionStatus = 'Starting conversion..';

        url = "/websites/switchServer";

        var data = {
            domainName: $("#domainNamePage").text(),
            phpSelection: $scope.phpSelection,
            server: server
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialData, cantLoadInitialData);

        function ListInitialData(response) {
            if (response.data.status === 1) {
                statusFile = response.data.tempStatusPath;
                statusFunc();

            } else {
                $scope.cyberpanelloading = true;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialData(response) {
            $scope.cyberpanelloading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });
        }


    };

    function statusFunc() {
        $scope.cyberpanelloading = false;
        url = "/websites/statusFunc";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            if (response.data.status === 1) {
                if (response.data.abort === 1) {
                    $scope.functionProgress = {"width": "100%"};
                    $scope.functionStatus = response.data.currentStatus;
                    $scope.cyberpanelloading = true;
                    $timeout.cancel();
                    $scope.getSwitchStatus();
                } else {
                    $scope.functionProgress = {"width": response.data.installationProgress + "%"};
                    $scope.functionStatus = response.data.currentStatus;
                    $timeout(statusFunc, 3000);
                }

            } else {
                $scope.cyberpanelloading = true;
                $scope.functionStatus = response.data.error_message;
                $scope.functionProgress = {"width": response.data.installationProgress + "%"};
                $timeout.cancel();
            }

        }

        function cantLoadInitialData(response) {
            $scope.functionProgress = {"width": response.data.installationProgress + "%"};
            $scope.functionStatus = 'Could not connect to server, please refresh this page.';
            $timeout.cancel();
        }

    }


    $scope.tuneSettings = function () {
        $scope.cyberpanelloading = false;

        url = "/websites/tuneSettings";

        var data = {
            domainName: $("#domainNamePage").text(),
            pmMaxChildren: $scope.pmMaxChildren,
            pmStartServers: $scope.pmStartServers,
            pmMinSpareServers: $scope.pmMinSpareServers,
            pmMaxSpareServers: $scope.pmMaxSpareServers,
            phpPath: $scope.phpPath
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialData, cantLoadInitialData);

        function ListInitialData(response) {
            $scope.cyberpanelloading = true;
            if (response.data.status === 1) {

                new PNotify({
                    title: 'Success',
                    text: 'Changes successfully applied.',
                    type: 'success'
                });

            } else {
                $scope.cyberpanelloading = true;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialData(response) {
            $scope.cyberpanelloading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });
        }


    };

    $scope.saveApacheConfig = function () {
        $scope.cyberpanelloading = false;

        url = "/websites/saveApacheConfigsToFile";

        var data = {
            domainName: $("#domainNamePage").text(),
            configData: $scope.configData
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialData, cantLoadInitialData);

        function ListInitialData(response) {
            $scope.cyberpanelloading = true;
            if (response.data.status === 1) {

                new PNotify({
                    title: 'Success',
                    text: 'Changes successfully applied.',
                    type: 'success'
                });

            } else {
                $scope.cyberpanelloading = true;
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }

        }

        function cantLoadInitialData(response) {
            $scope.cyberpanelloading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });
        }


    };

});


app.controller('createDockerPackage', function ($scope, $http, $window) {
    $scope.cyberpanelLoading = true;

    $scope.createdockerpackage = function () {

        $scope.cyberpanelLoading = false;
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            name: $scope.packagesname,
            cpu: $scope.CPU,
            Memory: $scope.Memory,
            Bandwidth: $scope.Bandwidth,
            disk: $scope.disk
        };


        dataurl = "/websites/AddDockerpackage";

        $http.post(dataurl, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully Saved.',
                    type: 'success'
                });
                setTimeout(function() {
                    location.reload();
                }, 1500);

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    }


    $scope.Getpackage = function (packid) {

        $scope.cyberpanelLoading = false;
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            id: packid,
        };


        dataurl = "/websites/Getpackage";

        $http.post(dataurl, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            console.log('Getpackage response:', response.data);
            if (response.data.status === 1) {
                // Log the exact structure to understand the response
                console.log('Response error_message:', response.data.error_message);
                
                // Handle different possible response formats
                var packageData = response.data.error_message;
                if (packageData) {
                    // Check if data is nested in obj property or direct
                    var data = packageData.obj || packageData;
                    
                    $scope.U_Name = data.Name;
                    $scope.U_CPU = data.CPU || data.CPUs;
                    $scope.U_Memory = data.Memory || data.Ram;
                    $scope.U_Bandwidth = data.Bandwidth;
                    $scope.U_DiskSpace = data.DiskSpace;
                    $scope.EditID = packid;
                    
                    console.log('Set modal data:', {
                        Name: $scope.U_Name,
                        CPU: $scope.U_CPU,
                        Memory: $scope.U_Memory,
                        Bandwidth: $scope.U_Bandwidth,
                        DiskSpace: $scope.U_DiskSpace
                    });
                    
                    // Force Angular to update the view
                    if (!$scope.$$phase) {
                        $scope.$apply();
                    }
                    
                    // Also manually update the form fields as a fallback
                    setTimeout(function() {
                        $('#EditPackage input[ng-model="U_Name"]').val($scope.U_Name);
                        $('#EditPackage input[ng-model="U_CPU"]').val($scope.U_CPU);
                        $('#EditPackage input[ng-model="U_Memory"]').val($scope.U_Memory);
                        $('#EditPackage input[ng-model="U_Bandwidth"]').val($scope.U_Bandwidth);
                        $('#EditPackage input[ng-model="U_DiskSpace"]').val($scope.U_DiskSpace);
                        
                        console.log('Manually updated form fields');
                        
                        // Ensure Angular knows about the manual updates
                        $('#EditPackage').find('input[ng-model="U_CPU"]').trigger('input');
                        $('#EditPackage').find('input[ng-model="U_Memory"]').trigger('input');
                        $('#EditPackage').find('input[ng-model="U_Bandwidth"]').trigger('input');
                        $('#EditPackage').find('input[ng-model="U_DiskSpace"]').trigger('input');
                        
                        // Show the modal
                        $('#EditPackage').modal('show');
                    }, 200);
                } else {
                    console.error('Package data not found in response');
                }

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    }


    $scope.SaveUpdate = function () {

        $scope.cyberpanelLoading = false;
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            id: $scope.EditID,
            CPU: $scope.U_CPU,
            RAM: $scope.U_Memory,
            Bandwidth: $scope.U_Bandwidth,
            DiskSpace: $scope.U_DiskSpace,
        };


        dataurl = "/websites/Updatepackage";

        $http.post(dataurl, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully Updated.',
                    type: 'success'
                });
                setTimeout(function() {
                    location.reload();
                }, 1500);
                $('#EditPackage').modal('hide');
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    }

    var FinalDeletepackageURL;
    $scope.Deletepackage = function (url) {
        FinalDeletepackageURL = url;
        console.log('Delete URL set to:', FinalDeletepackageURL);
        
        // Show the delete confirmation modal
        $('#packagedelete').modal('show');
    }

    $scope.ConfirmDelete = function () {
        console.log('Confirming delete with URL:', FinalDeletepackageURL);
        
        if (!FinalDeletepackageURL) {
            console.error('No delete URL set');
            return;
        }
        
        // Hide modal and redirect after a small delay
        $('#packagedelete').modal('hide');
        
        setTimeout(function() {
            window.location.href = FinalDeletepackageURL;
        }, 300);
    }

})
app.controller('AssignPackage', function ($scope, $http,) {
    $scope.cyberpanelLoading = true;
    $scope.AddAssignment = function () {
        $scope.cyberpanelLoading = false;
        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            package: $('#packageSelection').val(),
            user: $scope.userSelection,
        };


        dataurl = "/websites/AddAssignment";

        $http.post(dataurl, data, config).then(ListInitialDatas, cantLoadInitialDatas);

        function ListInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            if (response.data.status === 1) {
                new PNotify({
                    title: 'Success',
                    text: 'Successfully saved.',
                    type: 'success'
                });
                
                // Reload page to show new assignment
                setTimeout(function() {
                    location.reload();
                }, 1500);

            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });
            }
        }

        function cantLoadInitialDatas(response) {
            $scope.cyberpanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Could not connect to server, please refresh this page.',
                type: 'error'
            });


        }
    }

    var FinalDeletepackageURL;
    $scope.Deleteassingment = function (url) {
        FinalDeletepackageURL = url;
        // console.log(FinalDeletepackageURL);
    }

    $scope.ConfirmDelete = function () {
        window.location.href = FinalDeletepackageURL
    }

})
app.controller('createDockerSite', function ($scope, $http, $timeout) {
    $scope.cyberpanelLoading = true;
    $scope.installationDetailsForm = false;
    $scope.installationProgress = true;
    $scope.errorMessageBox = true;
    $scope.success = true;
    $scope.couldNotConnect = true;
    $scope.goBackDisable = true;

    var statusFile;

    $scope.createdockersite = function () {

        $scope.cyberpanelLoading = false;
        $scope.installationDetailsForm = true;
        $scope.installationProgress = false;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;

        $scope.currentStatus = "Starting creation..";


        url = "/websites/submitDockerSiteCreation";

        var package = $scope.packageForWebsite;


        var data = {
            sitename: $scope.siteName,
            Owner: $scope.userSelection,
            Domain: $scope.domainNameCreate,
            MysqlCPU: $scope.CPUMysql,
            MYsqlRam: $scope.rammysql,
            SiteCPU: $scope.CPUSite,
            SiteRam: $scope.RamSite,
            App: $scope.App,
            WPusername: $scope.WPUsername,
            WPemal: $scope.wpEmail,
            WPpasswd: $scope.WPpassword
        };


        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {
            console.log('.........................')
            if (response.data.installStatus === 1) {
                console.log(response.data.installsatus)
                statusFile = response.data.tempStatusPath;
                getCreationStatus();
            } else {

                $scope.cyberpanelLoading = true;
                $scope.installationDetailsForm = true;
                $scope.installationProgress = false;
                $scope.errorMessageBox = false;
                $scope.success = true;
                $scope.couldNotConnect = true;
                $scope.goBackDisable = false;

                $scope.errorMessage = response.data.error_message;
            }


        }

        function cantLoadInitialDatas(response) {

            $scope.cyberpanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    };
    $scope.goBack = function () {
        $scope.cyberpanelLoading = true;
        $scope.installationDetailsForm = false;
        $scope.installationProgress = true;
        $scope.errorMessageBox = true;
        $scope.success = true;
        $scope.couldNotConnect = true;
        $scope.goBackDisable = true;
        $("#installProgress").css("width", "0%");
    };

    function getCreationStatus() {

        url = "/websites/installWordpressStatus";

        var data = {
            statusFile: statusFile
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };


        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.abort === 1) {

                if (response.data.installStatus === 1) {

                    $scope.cyberpanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = true;
                    $scope.success = false;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $("#installProgress").css("width", "100%");
                    $scope.installPercentage = "100";
                    $scope.currentStatus = response.data.currentStatus;
                    $timeout.cancel();

                } else {

                    $scope.cyberpanelLoading = true;
                    $scope.installationDetailsForm = true;
                    $scope.installationProgress = false;
                    $scope.errorMessageBox = false;
                    $scope.success = true;
                    $scope.couldNotConnect = true;
                    $scope.goBackDisable = false;

                    $scope.errorMessage = response.data.error_message;

                    $("#installProgress").css("width", "0%");
                    $scope.installPercentage = "0";
                    $scope.goBackDisable = false;

                }

            } else {
                $("#installProgress").css("width", response.data.installationProgress + "%");
                $scope.installPercentage = response.data.installationProgress;
                $scope.currentStatus = response.data.currentStatus;
                $timeout(getCreationStatus, 1000);
            }

        }

        function cantLoadInitialDatas(response) {

            $scope.cyberpanelLoading = true;
            $scope.installationDetailsForm = true;
            $scope.installationProgress = false;
            $scope.errorMessageBox = true;
            $scope.success = true;
            $scope.couldNotConnect = false;
            $scope.goBackDisable = false;

        }


    }

})


app.controller('listDockersite', function ($scope, $http) {

    $scope.cyberPanelLoading = true;


    $scope.currentPage = 1;
    $scope.recordsToShow = 10;

    $scope.fetchDockersiteFromDB = function () {

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            page: $scope.currentPage,
            recordsToShow: $scope.recordsToShow
        };


        dataurl = "/websites/fetchDockersite";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            $scope.cyberPanelLoading = false;
            if (response.data.listWebSiteStatus === 1) {

                $scope.WebSitesList = JSON.parse(response.data.data);
                $scope.pagination = response.data.pagination;
                $scope.clients = JSON.parse(response.data.data);
                $("#listFail").hide();
            } else {
                $("#listFail").fadeIn();
                $scope.errorMessage = response.data.error_message;

            }
        }

        function cantLoadInitialData(response) {
            $scope.cyberPanelLoading = false;
        }


    };
    $scope.fetchDockersiteFromDB();

    $scope.cyberPanelLoading = true;


    $scope.cyberPanelLoading = true;

    $scope.searchWebsites = function () {

        $scope.cyberPanelLoading = false;

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        var data = {
            patternAdded: $scope.patternAdded
        };

        dataurl = "/websites/searchWebsites";

        $http.post(dataurl, data, config).then(ListInitialData, cantLoadInitialData);


        function ListInitialData(response) {
            $scope.cyberPanelLoading = true;
            if (response.data.listWebSiteStatus === 1) {

                var finalData = JSON.parse(response.data.data);
                $scope.WebSitesList = finalData;
                $("#listFail").hide();
            } else {
                new PNotify({
                    title: 'Operation Failed!',
                    text: response.data.error_message,
                    type: 'error'
                });

            }
        }

        function cantLoadInitialData(response) {
            $scope.cyberPanelLoading = true;
            new PNotify({
                title: 'Operation Failed!',
                text: 'Connect disrupted, refresh the page.',
                type: 'error'
            });
        }


    };

    $scope.getFurtherWebsitesFromDB = function () {
        $scope.fetchDockersiteFromDB();
    };

    var deletedockersiteurl;
    $scope.DeleteDockersite = function (url, id) {
        // console.log(url)
        // console.log(id)
        deletedockersiteurl = url + id;
    }

    $scope.ConfirmDelete = function () {
        window.location.href = deletedockersiteurl;
    }


});


app.controller('BuyAddons', function ($scope, $http) {


    $scope.cyberpanelLoading = true;
    $scope.sftpHide = true;
    $scope.localHide = true;

    $scope.PaypalBuyNowAddons = function (planName, monthlyPrice, yearlyPrice, lifetime, months) {

        const baseURL = 'https://platform.cyberpersons.com/Billing/AddOnOrderPaypal';
        // Get the current URL
        var currentURL = window.location.href;

// Find the position of the question mark
        const queryStringIndex = currentURL.indexOf('?');

// Check if there is a query string
        currentURL = queryStringIndex !== -1 ? currentURL.substring(0, queryStringIndex) : currentURL;

        // Encode parameters to make them URL-safe
        const params = new URLSearchParams({
            planName: planName,
            monthlyPrice: monthlyPrice,
            yearlyPrice: yearlyPrice,
            returnURL: currentURL,  // Add the current URL as a query parameter
            months: months
        });

        // Build the complete URL with query string
        const fullURL = `${baseURL}?${params.toString()}`;

        // Redirect to the constructed URL

        window.location.href = fullURL;

    }

})

app.controller('launchChild', function ($scope, $http) {

    $scope.logFileLoading = true;
    $scope.logsFeteched = true;
    $scope.couldNotFetchLogs = true;
    $scope.couldNotConnect = true;
    $scope.fetchedData = true;
    $scope.hideLogs = true;
    $scope.hideErrorLogs = true;

    $scope.hidelogsbtn = function () {
        $scope.hideLogs = true;
    };

    $scope.hideErrorLogsbtn = function () {
        $scope.hideLogs = true;
    };

    // Watch for when the scope variables are initialized from ng-init
    $scope.$watch('childDomainName', function(newVal) {
        if (newVal) {
            $scope.fileManagerURL = "/filemanager/" + $scope.masterDomain;
            $scope.previewUrl = "/preview/" + $scope.childDomainName + "/";
            $scope.wordPressInstallURL = "/websites/" + $scope.childDomainName + "/wordpressInstall";
            $scope.joomlaInstallURL = "/websites/" + $scope.childDomainName + "/joomlaInstall";
            $scope.setupGit = "/websites/" + $scope.childDomainName + "/setupGit";
            $scope.installPrestaURL = "/websites/" + $scope.childDomainName + "/installPrestaShop";
            $scope.installMagentoURL = "/websites/" + $scope.childDomainName + "/installMagento";
        }
    });

    var logType = 0;
    $scope.pageNumber = 1;

    $scope.fetchLogs = function (type) {

        var pageNumber = $scope.pageNumber;


        if (type == 3) {
            pageNumber = $scope.pageNumber + 1;
            $scope.pageNumber = pageNumber;
        } else if (type == 4) {
            pageNumber = $scope.pageNumber - 1;
            $scope.pageNumber = pageNumber;
        } else {
            logType = type;
        }


        $scope.logFileLoading = false;
        $scope.logsFeteched = true;
        $scope.couldNotFetchLogs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedData = false;
        $scope.hideErrorLogs = true;


        url = "/websites/getDataFromLogFile";

        var domainNamePage = $("#domainNamePage").text();


        var data = {
            logType: logType,
            virtualHost: domainNamePage,
            page: pageNumber,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.logstatus === 1) {


                $scope.logFileLoading = true;
                $scope.logsFeteched = false;
                $scope.couldNotFetchLogs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedData = false;
                $scope.hideLogs = false;


                $scope.records = JSON.parse(response.data.data);

            } else {

                $scope.logFileLoading = true;
                $scope.logsFeteched = true;
                $scope.couldNotFetchLogs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = false;


                $scope.errorMessage = response.data.error_message;
                console.log(domainNamePage)

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.logFileLoading = true;
            $scope.logsFeteched = true;
            $scope.couldNotFetchLogs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedData = true;
            $scope.hideLogs = false;

        }


    };

    $scope.errorPageNumber = 1;


    $scope.fetchErrorLogs = function (type) {

        var errorPageNumber = $scope.errorPageNumber;


        if (type === 3) {
            errorPageNumber = $scope.errorPageNumber + 1;
            $scope.errorPageNumber = errorPageNumber;
        } else if (type === 4) {
            errorPageNumber = $scope.errorPageNumber - 1;
            $scope.errorPageNumber = errorPageNumber;
        } else {
            logType = type;
        }

        // notifications

        $scope.logFileLoading = false;
        $scope.logsFeteched = true;
        $scope.couldNotFetchLogs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedData = true;
        $scope.hideErrorLogs = true;
        $scope.hideLogs = false;


        url = "/websites/fetchErrorLogs";

        var domainNamePage = $("#domainNamePage").text();


        var data = {
            virtualHost: domainNamePage,
            page: errorPageNumber,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.logstatus === 1) {


                // notifications

                $scope.logFileLoading = true;
                $scope.logsFeteched = false;
                $scope.couldNotFetchLogs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = false;
                $scope.hideErrorLogs = false;


                $scope.errorLogsData = response.data.data;

            } else {

                // notifications

                $scope.logFileLoading = true;
                $scope.logsFeteched = true;
                $scope.couldNotFetchLogs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedData = true;
                $scope.hideLogs = true;
                $scope.hideErrorLogs = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            // notifications

            $scope.logFileLoading = true;
            $scope.logsFeteched = true;
            $scope.couldNotFetchLogs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedData = true;
            $scope.hideLogs = true;
            $scope.hideErrorLogs = true;

        }


    };

    ///////// Configurations Part

    $scope.configurationsBox = true;
    $scope.configsFetched = true;
    $scope.couldNotFetchConfigs = true;
    $scope.couldNotConnect = true;
    $scope.fetchedConfigsData = true;
    $scope.configFileLoading = true;
    $scope.configSaved = true;
    $scope.couldNotSaveConfigurations = true;

    $scope.hideconfigbtn = function () {

        $scope.configurationsBox = true;
    };

    $scope.fetchConfigurations = function () {


        $scope.hidsslconfigs = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = true;


        //Rewrite rules
        $scope.configurationsBoxRewrite = true;
        $scope.rewriteRulesFetched = true;
        $scope.couldNotFetchRewriteRules = true;
        $scope.rewriteRulesSaved = true;
        $scope.couldNotSaveRewriteRules = true;
        $scope.fetchedRewriteRules = true;
        $scope.saveRewriteRulesBTN = true;

        ///

        $scope.configFileLoading = false;


        url = "/websites/getDataFromConfigFile";

        var virtualHost = $("#childDomain").text();


        var data = {
            virtualHost: virtualHost,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.configstatus === 1) {

                //Rewrite rules

                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;

                ///

                $scope.configurationsBox = false;
                $scope.configsFetched = false;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = false;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = false;


                $scope.configData = response.data.configData;

            } else {

                //Rewrite rules
                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;

                ///
                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = false;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            //Rewrite rules
            $scope.configurationsBoxRewrite = true;
            $scope.rewriteRulesFetched = true;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = true;
            ///

            $scope.configurationsBox = false;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;


        }


    };

    $scope.saveCongiruations = function () {

        $scope.configFileLoading = false;


        url = "/websites/saveConfigsToFile";

        var virtualHost = $("#childDomain").text();
        var configData = $scope.configData;


        var data = {
            virtualHost: virtualHost,
            configData: configData,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.configstatus == 1) {

                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = false;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;


            } else {
                $scope.configurationsBox = false;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.couldNotConnect = true;
                $scope.fetchedConfigsData = false;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = false;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configurationsBox = false;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.couldNotConnect = false;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;


        }


    };


    ///////// Rewrite Rules

    $scope.configurationsBoxRewrite = true;
    $scope.rewriteRulesFetched = true;
    $scope.couldNotFetchRewriteRules = true;
    $scope.rewriteRulesSaved = true;
    $scope.couldNotSaveRewriteRules = true;
    $scope.fetchedRewriteRules = true;
    $scope.saveRewriteRulesBTN = true;

    $scope.hideRewriteRulesbtn = function () {
        $scope.configurationsBoxRewrite = true;
    };


    $scope.fetchRewriteFules = function () {

        $scope.hidsslconfigs = true;
        $scope.configurationsBox = true;
        $scope.changePHPView = true;


        $scope.configurationsBox = true;
        $scope.configsFetched = true;
        $scope.couldNotFetchConfigs = true;
        $scope.couldNotConnect = true;
        $scope.fetchedConfigsData = true;
        $scope.configFileLoading = true;
        $scope.configSaved = true;
        $scope.couldNotSaveConfigurations = true;
        $scope.saveConfigBtn = true;

        $scope.configFileLoading = false;


        url = "/websites/getRewriteRules";

        var virtualHost = $("#childDomain").text();


        var data = {
            virtualHost: virtualHost,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.rewriteStatus == 1) {


                // from main

                $scope.configurationsBox = true;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.fetchedConfigsData = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;

                // main ends

                $scope.configFileLoading = true;

                //


                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = false;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = false;
                $scope.saveRewriteRulesBTN = false;
                $scope.couldNotConnect = true;


                $scope.rewriteRules = response.data.rewriteRules;

            } else {
                // from main
                $scope.configurationsBox = true;
                $scope.configsFetched = true;
                $scope.couldNotFetchConfigs = true;
                $scope.fetchedConfigsData = true;
                $scope.configFileLoading = true;
                $scope.configSaved = true;
                $scope.couldNotSaveConfigurations = true;
                $scope.saveConfigBtn = true;
                // from main

                $scope.configFileLoading = true;

                ///

                $scope.configurationsBoxRewrite = true;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = false;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;
                $scope.couldNotConnect = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {
            // from main

            $scope.configurationsBox = true;
            $scope.configsFetched = true;
            $scope.couldNotFetchConfigs = true;
            $scope.fetchedConfigsData = true;
            $scope.configFileLoading = true;
            $scope.configSaved = true;
            $scope.couldNotSaveConfigurations = true;
            $scope.saveConfigBtn = true;

            // from main

            $scope.configFileLoading = true;

            ///

            $scope.configurationsBoxRewrite = true;
            $scope.rewriteRulesFetched = true;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = true;

            $scope.couldNotConnect = false;


        }


    };

    $scope.saveRewriteRules = function () {

        $scope.configFileLoading = false;


        url = "/websites/saveRewriteRules";

        var virtualHost = $("#childDomain").text();
        var rewriteRules = $scope.rewriteRules;


        var data = {
            virtualHost: virtualHost,
            rewriteRules: rewriteRules,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.rewriteStatus == 1) {

                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = true;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = false;
                $scope.couldNotSaveRewriteRules = true;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = true;
                $scope.configFileLoading = true;


            } else {
                $scope.configurationsBoxRewrite = false;
                $scope.rewriteRulesFetched = false;
                $scope.couldNotFetchRewriteRules = true;
                $scope.rewriteRulesSaved = true;
                $scope.couldNotSaveRewriteRules = false;
                $scope.fetchedRewriteRules = true;
                $scope.saveRewriteRulesBTN = false;

                $scope.configFileLoading = true;


                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configurationsBoxRewrite = false;
            $scope.rewriteRulesFetched = false;
            $scope.couldNotFetchRewriteRules = true;
            $scope.rewriteRulesSaved = true;
            $scope.couldNotSaveRewriteRules = true;
            $scope.fetchedRewriteRules = true;
            $scope.saveRewriteRulesBTN = false;

            $scope.configFileLoading = true;

            $scope.couldNotConnect = false;


        }


    };


    //////// SSL Part

    $scope.sslSaved = true;
    $scope.couldNotSaveSSL = true;
    $scope.hidsslconfigs = true;
    $scope.couldNotConnect = true;


    $scope.hidesslbtn = function () {
        $scope.hidsslconfigs = true;
    };

    $scope.addSSL = function () {
        $scope.hidsslconfigs = false;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = true;
    };


    $scope.saveSSL = function () {


        $scope.configFileLoading = false;

        url = "/websites/saveSSL";

        var virtualHost = $("#childDomain").text();
        var cert = $scope.cert;
        var key = $scope.key;


        var data = {
            virtualHost: virtualHost,
            cert: cert,
            key: key,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {

            if (response.data.sslStatus === 1) {

                $scope.sslSaved = false;
                $scope.couldNotSaveSSL = true;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;


            } else {

                $scope.sslSaved = true;
                $scope.couldNotSaveSSL = false;
                $scope.couldNotConnect = true;
                $scope.configFileLoading = true;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.sslSaved = true;
            $scope.couldNotSaveSSL = true;
            $scope.couldNotConnect = false;
            $scope.configFileLoading = true;


        }

    };


    //// Change PHP Master

    $scope.failedToChangePHPMaster = true;
    $scope.phpChangedMaster = true;
    $scope.couldNotConnect = true;

    $scope.changePHPView = true;


    $scope.hideChangePHPMaster = function () {
        $scope.changePHPView = true;
    };

    $scope.changePHPMaster = function () {
        $scope.hidsslconfigs = true;
        $scope.configurationsBox = true;
        $scope.configurationsBoxRewrite = true;
        $scope.changePHPView = false;
    };


    $scope.changePHPVersionMaster = function (childDomain, phpSelection) {

        // notifcations

        $scope.configFileLoading = false;

        var url = "/websites/changePHP";

        var data = {
            childDomain: $("#childDomain").text(),
            phpSelection: $scope.phpSelectionMaster,
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changePHP === 1) {

                $scope.configFileLoading = true;
                $scope.websiteDomain = $("#childDomain").text();


                // notifcations

                $scope.failedToChangePHPMaster = true;
                $scope.phpChangedMaster = false;
                $scope.couldNotConnect = true;


            } else {

                $scope.configFileLoading = true;
                $scope.errorMessage = response.data.error_message;

                // notifcations

                $scope.failedToChangePHPMaster = false;
                $scope.phpChangedMaster = true;
                $scope.couldNotConnect = true;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.configFileLoading = true;

            // notifcations

            $scope.failedToChangePHPMaster = true;
            $scope.phpChangedMaster = true;
            $scope.couldNotConnect = false;

        }

    };


    /// Open_basedir protection

    $scope.baseDirLoading = true;
    $scope.operationFailed = true;
    $scope.operationSuccessfull = true;
    $scope.couldNotConnect = true;
    $scope.openBaseDirBox = true;


    $scope.openBaseDirView = function () {
        $scope.openBaseDirBox = false;
    };

    $scope.hideOpenBasedir = function () {
        $scope.openBaseDirBox = true;
    };

    $scope.applyOpenBasedirChanges = function (childDomain, phpSelection) {

        // notifcations

        $scope.baseDirLoading = false;
        $scope.operationFailed = true;
        $scope.operationSuccessfull = true;
        $scope.couldNotConnect = true;
        $scope.openBaseDirBox = false;


        var url = "/websites/changeOpenBasedir";

        var data = {
            domainName: $("#childDomain").text(),
            openBasedirValue: $scope.openBasedirValue
        };

        var config = {
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            }
        };

        $http.post(url, data, config).then(ListInitialDatas, cantLoadInitialDatas);


        function ListInitialDatas(response) {


            if (response.data.changeOpenBasedir === 1) {

                $scope.baseDirLoading = true;
                $scope.operationFailed = true;
                $scope.operationSuccessfull = false;
                $scope.couldNotConnect = true;
                $scope.openBaseDirBox = false;

            } else {

                $scope.baseDirLoading = true;
                $scope.operationFailed = false;
                $scope.operationSuccessfull = true;
                $scope.couldNotConnect = true;
                $scope.openBaseDirBox = false;

                $scope.errorMessage = response.data.error_message;

            }


        }

        function cantLoadInitialDatas(response) {

            $scope.baseDirLoading = true;
            $scope.operationFailed = true;
            $scope.operationSuccessfull = true;
            $scope.couldNotConnect = false;
            $scope.openBaseDirBox = false;


        }

    }

});