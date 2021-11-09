
console.log("script.js loaded!");


// Variables

const vTotalInfo = '8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a';




// Functions
const webSiteScan  = () => {

  
 

// winner winner chicken dinner
//curl --request POST --url https://www.virustotal.com/api/v3/urls --header "x-apikey: 8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a" --form url="www.google.com"

//https://www.virustotal.com/vtapi/v2/url/report?apikey=8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a&resource='www.google.com'


    let myRequestURL = "https://www.virustotal.com/api/v3/urls";
   
    console.log(vTotalInfo);
  

 //debugger;
 //tmpStr = JSON.stringify("www.google.com");
 let formData = new FormData()
 formData.append('url', 'www.google.com');
 myRequestObject = {
     method: 'POST',
    // headers: {'x-apikey' : vTotalInfo},
    headers: {'x-apikey' :'8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a' },
     body: formData,
     mode: 'no-cors',
     Credentials : 'same-origin'
     
    
 }

 //origin = "www.mozilla.org";
 console.log(myRequestObject);

   fetch(myRequestURL, myRequestObject).then(function(response){ 
   // fetch(myRequestURL, {method:'POST', headers:{'x-apikey' : vTotalInfo  }, body:{'url':'www.google.com'}, mode:'no-cors', credentials: 'same-origin'}).then(function(response) {

        if(response.ok) {
            response.json().then(function(data) {
                console.log(data); 
                console.log(response.status);
            
        });

   
        } else {
            alert("Error:  Web Security failed to retrieve");
            console.log(response.status);


        }
    });


//version 2.0

// let formData2 = new FormData()
//  formData2.append('url', 'www.google.com');
//  myRequestObject2 = {
//      method: 'POST',
//     // headers: {'x-apikey' : vTotalInfo},
//     headers: {'apikey' :'8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a'},
//      body: formData2,
//      mode: 'no-cors'
//  }
//  console.log(myRequestObject2);

//  let myRequestURL2 = "https://www.virustotal.com/vtapi/v2/url/scan";

//    fetch(myRequestURL2, myRequestObject2).then(function(response){ 
//    // fetch(myRequestURL, {method:'POST', headers:{'x-apikey' : vTotalInfo  }, body:{'url':'www.google.com'}, mode:'no-cors', credentials: 'same-origin'}).then(function(response) {

//         if(response.ok) {
//             response.json().then(function(data) {
//                 console.log(data); 
//                 console.log(response.status);
            
//         });

   
//         } else {
//             alert("Error:  Web Security failed to retrieve");
//             console.log(response.status);


//         }
//     });
};








// Function calls


webSiteScan();





// Listeners


