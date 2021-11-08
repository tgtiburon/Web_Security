
console.log("script.js loaded!");


// Variables

vTotalInfo = "8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a";




// Functions
const startUp  = () => {

 //   curl --request POST 
 // --url https://www.virustotal.com/api/v3/urls 
 // --header 'x-apikey: 8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' 
 // --form url='www.google.com'


 
  letTmpObj = curl --request POST \
  --url https://www.virustotal.com/api/v3/urls \
  --header 'x-apikey: 8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' \
  --form url='www.google.com'




   // curl --request POST --url https://www.virustotal.com/vtapi/v2/url/scan --header 'x-apikey: $8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' --form url= 'https://tines.io'
  
   // curl --POST --https://www.virustotal.com/vtapi/v2/url/scan --'x-apikey: $8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' --url= 'https://tines.io'
  


  console.log("after curl");

    //letTempObj = 



   // cityName = city;
      
    //let apiUrl = "https://api.openweathermap.org/data/2.5/weather?q=" + cityName + "&units=imperial" + "&appid="  + yekIPA;
    //let tmpObj = curl --request POST --url https://www.virustotal.com/vtapi/v2/url/scan --data 'apikey=' + vtTotalInfo + --data 'url=www.google.com';

   // curl  --url "https://www.virustotal.com/api/v3/urls" --header 'x-apikey:' + vt+  --form url='www.google.com'
   // curl  POST https://www.virustotal.com/api/v3/urls' + vtTotalInfo + 'www.google.com'
   // curl  https://www.virustotal.com/api/v3/urls<8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a>''www.google.com'
   // curl https://www.virustotal.com/api/v3/urls x-apikey:'8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' url='www.google.com'
    console.log(tmpObj);


   // curl --request POST --url https://www.virustotal.com/api/v3/urls --header 'x-apikey: 8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' --form url='www.google.com'


   // fetch(apiUrl).then(function(response) {
     //   if(response.ok) {
     //       response.json().then(function(data) {
               // displayRepos(data.items, language);
       //        coords = data;
       //        console.log(data);
              // localStorage.setItem("coords", JSON.stringify(data));

              // let lon = data.coord.lon;
               //let lat = data.coord.lat;
              // console.log("lat=" + lat + " lon= " + lon);


               // Use one Call API to get all the data we need
              
             //  getWeather(lon, lat);

       //     });
    //    } else {
    //        alert("Error:  Open Weather Failed");
    //    }
  //  });


};



// const getCoords = (city) => {
//     debugger;
    
//        // debugging
//        cityName = city;
      
//         let apiUrl = "https://api.openweathermap.org/data/2.5/weather?q=" + cityName + "&units=imperial" + "&appid="  + yekIPA;
    
//         fetch(apiUrl).then(function(response) {
//             if(response.ok) {
//                 response.json().then(function(data) {
//                    // displayRepos(data.items, language);
//                    coords = data;
//                    console.log(data);
//                    localStorage.setItem("coords", JSON.stringify(data));
    
//                    let lon = data.coord.lon;
//                    let lat = data.coord.lat;
//                    console.log("lat=" + lat + " lon= " + lon);
    
    
//                    // Use one Call API to get all the data we need
                  
//                    getWeather(lon, lat);
    
//                 });
//             } else {
//                 alert("Error:  Open Weather Failed");
//             }
//         });
//     };
//     // Use coordinates to get all the weather data needed.
//     const getWeather = (lon,lat) => {
//         debugger;
    
//         // using the one call api from openweathermap we can get everything we need.
//         let apiUrl = "https://api.openweathermap.org/data/2.5/onecall?lat=" + lat  + "&lon=" + lon 
//                      + "&units=imperial" + "&exclude=minutely,hourly,alerts"  + "&appid="  + yekIPA;
    
//         fetch(apiUrl).then(function(response) {
//             if(response.ok) {
//                 response.json().then(function(data) {
//                    // displayRepos(data.items, language);
//                    let weatherData = data;
//                    console.log(data);
//                    localStorage.setItem("weatherData", JSON.stringify(data));
//                    // get the lon and lat so I can call the one call api
    
//                    readWeatherData(weatherData);
                     
//                 });
//             } else {
//                 alert("Error:  Open Weather Failed");
//             }
//         });
    
    
//     }
    



// Function calls


startUp();





// Listeners


